"""Operator commands: migrations, configuration checks and recovery reports."""

from __future__ import annotations

import argparse
import json
import sys

from unitcompute.config import ConfigError, Settings, load_settings
from unitcompute.db.database import Database
from unitcompute.identities import IdentityLedger
from unitcompute.logging_setup import secure_process_defaults
from unitcompute.provisioning.factory import build_provisioner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unitcompute-admin")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="apply database migrations")
    sub.add_parser("check-config", help="validate configuration without starting services")
    report = sub.add_parser(
        "recovery-report", help="list deployments needing recovery, with AWS inventory"
    )
    report.add_argument(
        "--inventory",
        action="store_true",
        help="also list AWS resources tagged for each deployment (read-only)",
    )
    sub.add_parser(
        "orphan-report",
        help="read-only: UnitCompute-tagged AWS resources that no live deployment accounts for",
    )
    args = parser.parse_args(argv)
    secure_process_defaults()

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    db = Database(settings.database_path)

    if args.command == "migrate":
        applied = db.migrate()
        print(json.dumps({"applied": applied, "schema_version": db.schema_version()}))
        return 0
    if args.command == "check-config":
        print(
            json.dumps(
                {
                    "environment": settings.environment.value,
                    "auth_mode": settings.auth_mode.value,
                    "provisioner": settings.provisioner.value,
                    "agent_model": settings.agent_model or None,
                    "schema_version": db.schema_version(),
                }
            )
        )
        return 0

    db.require_current_schema()
    if args.command == "orphan-report":
        return _orphan_report(settings, db)
    with db.read() as conn:
        rows = conn.execute(
            "SELECT d.id, d.status, d.status_reason, d.provisioner, d.updated_at, "
            "j.id AS job_id, j.kind, j.status AS job_status, j.error_code "
            "FROM deployments d LEFT JOIN jobs j ON j.id = ("
            "  SELECT id FROM jobs WHERE deployment_id = d.id ORDER BY rowid DESC LIMIT 1) "
            "WHERE d.status = 'recovery_required' OR EXISTS (SELECT 1 FROM "
            "recovery_obligations o WHERE o.deployment_id = d.id AND o.discharged_at IS NULL "
            "AND o.evidence = 'uncaptured') ORDER BY d.updated_at"
        ).fetchall()
    provisioner = build_provisioner(settings) if args.inventory else None
    for row in rows:
        entry = dict(row)
        with db.read() as conn:
            known = IdentityLedger.known(conn, row["id"])
            obligations = conn.execute(
                "SELECT job_id, plan_id, reason, evidence, created_at FROM recovery_obligations "
                "WHERE deployment_id = ? AND discharged_at IS NULL ORDER BY id",
                (row["id"],),
            ).fetchall()
        entry["open_recovery_obligations"] = [dict(o) for o in obligations]
        entry["known_identities"] = known.all_ids
        entry["instances_without_root_disk"] = known.instances_without_root_disk()
        entry["observed_root_volumes"] = {k: sorted(v) for k, v in known.observed_roots.items()}
        if provisioner is not None:
            entry["aws_inventory"] = [
                {"type": r.resource_type, "id": r.resource_id, "state": r.state}
                for r in provisioner.owned_resources(row["id"])
            ]
        print(json.dumps(entry))
    return 0


def _orphan_report(settings: Settings, db: Database) -> int:
    """List every live resource in the region tagged ManagedBy=unitcompute that the database
    does not account for. Read-only: UnitCompute never deletes anything it cannot tie to a
    deployment's own approved plan, so removing these is a deliberate operator action."""
    provisioner = build_provisioner(settings)
    if provisioner is None:
        print("provisioning is disabled; there is nothing to scan", file=sys.stderr)
        return 2
    found = provisioner.managed_resources()
    with db.read() as conn:
        statuses = {
            r["id"]: r["status"] for r in conn.execute("SELECT id, status FROM deployments")
        }
        recorded: dict[str, set[str]] = {}
        for row in conn.execute("SELECT deployment_id, resource_id FROM deployment_resources"):
            recorded.setdefault(row["deployment_id"], set()).add(row["resource_id"])
    orphans = []
    tracked = 0
    for resource, deployment_id in found:
        if deployment_id is None:
            reason = "no_deployment_tag"
        elif deployment_id not in statuses:
            reason = "unknown_deployment"
        elif statuses[deployment_id] == "deleted":
            reason = "deployment_deleted"
        elif resource.resource_id not in recorded.get(deployment_id, set()):
            reason = "unrecorded_resource"
        else:
            tracked += 1
            continue
        orphans.append(
            {
                "type": resource.resource_type,
                "id": resource.resource_id,
                "state": resource.state,
                "deployment_id": deployment_id,
                "reason": reason,
            }
        )
    print(
        json.dumps(
            {
                "read_only": True,
                "region": settings.aws_region,
                "tracked": tracked,
                "orphans": orphans,
                "next_step": (
                    "UnitCompute does not delete these. Confirm each ID in the AWS console or "
                    "CLI (check the tags and the owner), then remove it deliberately; re-run "
                    "this report until orphans is empty."
                ),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
