"""Explicit offline, atomic SQLite-v7 import; never used by application startup.

Stop API/worker writers and copy their durable evidence/work directories separately.
Unknown schema/data is rejected, never repaired or discarded. Retain the source backup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psycopg import sql

from unitcompute.auth import Principal
from unitcompute.config import load_settings
from unitcompute.db.database import Database
from unitcompute.logging_setup import redact, redact_structured

TABLES = (
    "deployments",
    "plans",
    "jobs",
    "idempotency_records",
    "audit_events",
    "chat_sessions",
    "chat_messages",
    "worker_heartbeats",
    "agent_attempts",
    "deployment_resources",
    "identity_acknowledgements",
    "recovery_obligations",
)


SOURCE_COLUMNS = {
    "schema_migrations": ("version", "applied_at"),
    "deployments": (
        "id",
        "owner_id",
        "name",
        "disk_gib",
        "region",
        "instance_type",
        "provisioner",
        "status",
        "status_reason",
        "current_plan_id",
        "apply_attempted",
        "ami_id",
        "instance_id",
        "security_group_id",
        "ssm_ping_status",
        "created_at",
        "updated_at",
        "root_volume_id",
        "ec2_status",
        "connection_ready",
        "readiness_checked_at",
    ),
    "plans": (
        "id",
        "deployment_id",
        "owner_id",
        "kind",
        "status",
        "provisioner",
        "config_hash",
        "region",
        "state_key",
        "template_version",
        "template_hash",
        "terraform_version",
        "provider_versions_json",
        "account_id",
        "ami_id",
        "plan_path",
        "plan_hash",
        "preview_json",
        "cost_json",
        "created_at",
        "ready_at",
        "expires_at",
        "approved_by",
        "approved_at",
        "error_code",
        "error_message",
        "execution_hash",
        "prior_resource_ids_json",
    ),
    "jobs": (
        "id",
        "owner_id",
        "deployment_id",
        "plan_id",
        "kind",
        "status",
        "idempotency_scope",
        "idempotency_key",
        "payload_hash",
        "worker_id",
        "created_at",
        "started_at",
        "heartbeat_at",
        "finished_at",
        "error_code",
        "error_message",
        "result_json",
    ),
    "idempotency_records": (
        "owner_id",
        "scope",
        "idempotency_key",
        "payload_hash",
        "status_code",
        "response_json",
        "created_at",
    ),
    "audit_events": (
        "id",
        "occurred_at",
        "actor",
        "action",
        "deployment_id",
        "plan_id",
        "job_id",
        "request_id",
        "detail_json",
    ),
    "chat_sessions": ("id", "owner_id", "turns", "created_at", "updated_at"),
    "chat_messages": ("id", "session_id", "role", "content", "created_at"),
    "worker_heartbeats": ("worker_id", "started_at", "heartbeat_at", "healthy", "checks_json"),
    "agent_attempts": (
        "id",
        "owner_id",
        "session_id",
        "status",
        "idempotency_key",
        "payload_hash",
        "response_json",
        "created_at",
        "finished_at",
        "lease_expires_at",
    ),
    "deployment_resources": (
        "deployment_id",
        "resource_type",
        "resource_id",
        "parent_id",
        "source",
        "recorded_at",
    ),
    "identity_acknowledgements": (
        "id",
        "deployment_id",
        "instance_id",
        "operator",
        "reason",
        "recorded_at",
    ),
    "recovery_obligations": (
        "id",
        "deployment_id",
        "job_id",
        "plan_id",
        "reason",
        "evidence",
        "created_at",
        "discharged_at",
        "discharged_by_job_id",
    ),
}
SOURCE_OBJECTS = (
    "agent_attempts",
    "agent_attempts_idempotency",
    "agent_attempts_owner",
    "audit_events",
    "audit_events_deployment",
    "chat_messages",
    "chat_messages_session",
    "chat_sessions",
    "deployment_resources",
    "deployment_resources_no_delete",
    "deployment_resources_no_update",
    "deployment_resources_unique",
    "deployments",
    "deployments_one_live_per_owner",
    "deployments_owner",
    "idempotency_records",
    "identity_acknowledgements",
    "identity_acknowledgements_no_delete",
    "identity_acknowledgements_no_update",
    "jobs",
    "jobs_one_active_per_deployment",
    "jobs_queue",
    "plans",
    "plans_deployment",
    "recovery_obligations",
    "recovery_obligations_forward_only",
    "recovery_obligations_no_delete",
    "recovery_obligations_open",
    "schema_migrations",
    "worker_heartbeats",
)


def validate_source_json(value: Any) -> None:
    if redact_structured(value) != value:
        raise ValueError("unredacted sensitive JSON")
    if isinstance(value, dict):
        if (
            "format_version" in value and {"planned_values", "resource_changes"} & value.keys()
        ) or {"lineage", "serial", "terraform_version"} <= value.keys():
            raise ValueError("raw Terraform plan/state is not ordinary database data")
        for item in value.values():
            validate_source_json(item)
    elif isinstance(value, list):
        for item in value:
            validate_source_json(item)


def import_snapshot(
    db: Database, source: Path, *, issuer: str, source_auth: str = "jwt"
) -> dict[str, int]:
    """Import a quiescent v7 source once, or return the receipt for the same snapshot.

    The complete source schema and content fingerprint is committed with all rows. A
    failed import rolls everything back; an uncertain client result can be safely retried.
    Other source fingerprints require a new empty target, not a merge into live data.
    """
    if source_auth not in {"jwt", "development"}:
        raise ValueError("source_auth must be jwt or development")
    db.require_current_schema()
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as legacy:
        legacy.row_factory = sqlite3.Row
        legacy.execute("BEGIN")
        tables = {
            r[0]
            for r in legacy.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != {*TABLES, "schema_migrations"}:
            raise ValueError("unknown or missing source tables")
        objects = tuple(
            r[0]
            for r in legacy.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        if objects != SOURCE_OBJECTS:
            raise ValueError("unknown or missing source schema objects")
        versions = [
            r[0] for r in legacy.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
        if versions != list(range(1, 8)):
            raise ValueError("offline import requires a complete schema-v7 snapshot")
        if legacy.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or list(
            legacy.execute("PRAGMA foreign_key_check")
        ):
            raise ValueError("source integrity check failed")
        data: dict[str, list[dict[str, Any]]] = {}
        columns: dict[str, list[str]] = {}
        for table in TABLES:
            # Table names come only from the fixed allowlist above.
            columns[table] = [r[1] for r in legacy.execute(f'PRAGMA table_info("{table}")')]
            if tuple(columns[table]) != SOURCE_COLUMNS[table]:
                raise ValueError(f"unknown source columns in {table}")
            data[table] = [
                dict(r)
                for r in legacy.execute(
                    f'SELECT rowid AS _source_order, * FROM "{table}" ORDER BY rowid'  # noqa: S608 - fixed allowlist
                )
            ]
        schema = list(
            map(tuple, legacy.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
        )
        fingerprint = hashlib.sha256(
            json.dumps([schema, data, issuer, source_auth], sort_keys=True).encode()
        ).hexdigest()
        counts = {table: len(rows) for table, rows in data.items()}
        with db.transaction() as conn:
            receipt = conn.execute("SELECT fingerprint, counts FROM offline_imports").fetchone()
            if receipt:
                if receipt["fingerprint"] != fingerprint:
                    raise ValueError("target already imported a different snapshot")
                return dict(json.loads(receipt["counts"]))
            if any(
                conn.execute(
                    sql.SQL("SELECT 1 FROM {} LIMIT 1").format(sql.Identifier(t))
                ).fetchone()
                for t in (*TABLES, "resources", "users")
            ):
                raise ValueError("import target must be empty")
            for table in TABLES:
                target_columns = {
                    r[0]
                    for r in conn.execute(
                        (
                            "SELECT column_name FROM information_schema.columns WHERE "
                            "table_schema=%s AND table_name=%s"
                        ),
                        (db.schema, table),
                    )
                }
                if set(columns[table]) - target_columns:
                    raise ValueError(f"unknown source columns in {table}")
            owners = {r["owner_id"] for rows in data.values() for r in rows if "owner_id" in r}
            mapping = {}
            for owner in sorted(owners):
                principal = (
                    Principal(owner, "dev")
                    if source_auth == "development"
                    else Principal(owner, "jwt", issuer)
                )
                db.ensure_user(conn, principal)
                mapping[owner] = principal.owner_id
            # Chat sessions precede deployments with optional chat references; all current
            # plan references are restored after both sides of the cycle exist.
            order = ("chat_sessions", *[t for t in TABLES if t != "chat_sessions"])
            for table in order:
                for original in data[table]:
                    for name, value in original.items():
                        if isinstance(value, str) and redact(value) != value:
                            raise ValueError(f"unredacted sensitive source data: {table}.{name}")
                    row = dict(original)
                    source_order = row.pop("_source_order")
                    if table == "deployments":
                        row["cloud_owner_id"] = row["owner_id"]
                        # Account provenance lives in plan history, imported later in this
                        # same transaction. Restore the native identity only after it exists.
                        row["instance_id"] = None
                        row["current_plan_id"] = None
                    if "owner_id" in row:
                        row["owner_id"] = mapping[row["owner_id"]]
                    if table == "plans" and row.get("approved_by") in mapping:
                        row["approved_by"] = mapping[row["approved_by"]]
                    if table in {"deployments", "jobs"}:
                        row["sequence"] = source_order
                    for name, value in row.items():
                        if value is not None and name.endswith("_at"):
                            parsed = datetime.fromisoformat(value)
                            if parsed.tzinfo is None:
                                raise ValueError(f"timestamp lacks timezone: {table}.{name}")
                            row[name] = parsed.astimezone(UTC)
                        if value is not None and name.endswith("_json"):
                            parsed_json = json.loads(value)
                            try:
                                validate_source_json(parsed_json)
                            except ValueError as exc:
                                raise ValueError(
                                    f"unredacted sensitive source data: {table}.{name}: {exc}"
                                ) from exc
                    names = list(row)
                    conn.execute(
                        sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                            sql.Identifier(table),
                            sql.SQL(",").join(map(sql.Identifier, names)),
                            sql.SQL(",").join(sql.Placeholder() for _ in names),
                        ),
                        tuple(row[n] for n in names),
                    )
                target_columns = {
                    r[0]
                    for r in conn.execute(
                        (
                            "SELECT column_name FROM information_schema.columns WHERE "
                            "table_schema=%s AND table_name=%s"
                        ),
                        (db.schema, table),
                    )
                }
                for col in ("id", "sequence"):
                    if col not in target_columns:
                        continue
                    sequence_row = conn.execute(
                        "SELECT pg_get_serial_sequence(%s,%s)", (table, col)
                    ).fetchone()
                    sequence = sequence_row[0] if sequence_row else None
                    if sequence:
                        conn.execute(
                            sql.SQL(
                                "SELECT setval(%s, COALESCE(MAX({}), 1), MAX({}) IS NOT NULL) "
                                "FROM {}"
                            ).format(
                                sql.Identifier(col), sql.Identifier(col), sql.Identifier(table)
                            ),
                            (sequence,),
                        )
            # Native IDs and approval metadata become visible atomically with their history.
            for deployment in data["deployments"]:
                conn.execute(
                    "UPDATE deployments SET instance_id=%s,current_plan_id=%s WHERE id=%s",
                    (deployment["instance_id"], deployment["current_plan_id"], deployment["id"]),
                )
            conn.execute(
                "INSERT INTO offline_imports (fingerprint,counts) VALUES (%s,%s)",
                (fingerprint, json.dumps(counts)),
            )
        return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument(
        "--issuer", required=True, help="verified issuer of historical JWT subjects"
    )
    parser.add_argument(
        "--source-auth",
        choices=("jwt", "development"),
        default="jwt",
        help="explicit authentication provenance of every source owner",
    )
    args = parser.parse_args()
    settings = load_settings()
    result = import_snapshot(
        Database(settings.database_url, settings.database_schema),
        args.source,
        issuer=args.issuer,
        source_auth=args.source_auth,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
