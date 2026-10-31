"""Operator commands: migrations, configuration checks and recovery reports."""

from __future__ import annotations

import argparse
import json
import sys

from unitcompute.config import ConfigError, load_settings
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
    args = parser.parse_args(argv)
    secure_process_defaults()

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    db = Database(settings.database_url, settings.database_schema)

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
    with db.read() as conn:
        rows = conn.execute(
            "SELECT d.id, d.status, d.status_reason, d.provisioner, d.updated_at, "
            "j.id AS job_id, j.kind, j.status AS job_status, j.error_code "
            "FROM deployments d LEFT JOIN jobs j ON j.id = ("
            "  SELECT id FROM jobs WHERE deployment_id = d.id ORDER BY sequence DESC LIMIT 1) "
            "WHERE d.status = 'recovery_required' OR EXISTS (SELECT 1 FROM "
            "recovery_obligations o WHERE o.deployment_id = d.id "
            "AND (o.evidence = 'uncaptured' OR NOT "
            "recovery_obligation_valid(o.deployment_id,o.job_id,o.plan_id,o.evidence,"
            "o.discharged_at,o.discharged_by_job_id))) ORDER BY d.updated_at"
        ).fetchall()
    provisioner = build_provisioner(settings) if args.inventory else None
    for row in rows:
        entry = dict(row)
        with db.read() as conn:
            known = IdentityLedger.known(conn, row["id"])
            obligations = conn.execute(
                "SELECT job_id, plan_id, reason, evidence, created_at FROM recovery_obligations "
                "WHERE deployment_id = %s AND (discharged_at IS NULL OR NOT "
                "recovery_obligation_valid(deployment_id,job_id,plan_id,evidence,discharged_at,"
                "discharged_by_job_id)) ORDER BY id",
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
        print(json.dumps(entry, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
