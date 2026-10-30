"""Operator commands: migrations, configuration checks and recovery reports."""

from __future__ import annotations

import argparse
import json
import re
import sys

from unitcompute.config import ConfigError, load_settings
from unitcompute.db.database import Database, to_db_time, utcnow
from unitcompute.identities import IdentityLedger
from unitcompute.logging_setup import secure_process_defaults
from unitcompute.provisioning.factory import build_provisioner
from unitcompute.services.deployments import record_audit

_DEPLOYMENT = re.compile(r"^dep_[0-9a-f]{32}$")
_INSTANCE = re.compile(r"^i-[0-9a-f]{8,17}$")


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
    ack = sub.add_parser(
        "acknowledge-root-disk",
        help="record that a known instance's never-recorded root disk is confirmed gone",
    )
    ack.add_argument("deployment_id")
    ack.add_argument("instance_id")
    ack.add_argument("--operator", required=True, help="who verified it (recorded in audit)")
    ack.add_argument("--reason", required=True, help="how it was verified, e.g. CloudTrail")
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
    if args.command == "acknowledge-root-disk":
        return _acknowledge_root_disk(db, args)
    with db.read() as conn:
        rows = conn.execute(
            "SELECT d.id, d.status, d.status_reason, d.provisioner, d.updated_at, "
            "j.id AS job_id, j.kind, j.status AS job_status, j.error_code "
            "FROM deployments d LEFT JOIN jobs j ON j.id = ("
            "  SELECT id FROM jobs WHERE deployment_id = d.id ORDER BY rowid DESC LIMIT 1) "
            "WHERE d.status = 'recovery_required' ORDER BY d.updated_at"
        ).fetchall()
    provisioner = build_provisioner(settings) if args.inventory else None
    for row in rows:
        entry = dict(row)
        with db.read() as conn:
            known = IdentityLedger.known(conn, row["id"])
        entry["known_identities"] = known.all_ids
        entry["instances_without_root_disk"] = known.instances_without_root_disk()
        if provisioner is not None:
            entry["aws_inventory"] = [
                {"type": r.resource_type, "id": r.resource_id, "state": r.state}
                for r in provisioner.owned_resources(row["id"])
            ]
        print(json.dumps(entry))
    return 0


def _acknowledge_root_disk(db: Database, args: argparse.Namespace) -> int:
    if not (_DEPLOYMENT.fullmatch(args.deployment_id) and _INSTANCE.fullmatch(args.instance_id)):
        print("invalid deployment or instance ID", file=sys.stderr)
        return 2
    if not args.operator.strip() or not args.reason.strip():
        print("operator and reason are required", file=sys.stderr)
        return 2
    with db.transaction() as conn:
        known = IdentityLedger.known(conn, args.deployment_id)
        if args.instance_id not in known.instances:
            print("that instance is not recorded for this deployment", file=sys.stderr)
            return 1
        now = to_db_time(utcnow())
        conn.execute(
            "INSERT INTO identity_acknowledgements (deployment_id, instance_id, operator, "
            "reason, recorded_at) VALUES (?, ?, ?, ?, ?)",
            (args.deployment_id, args.instance_id, args.operator[:200], args.reason[:500], now),
        )
        record_audit(
            conn,
            actor=f"operator:{args.operator[:100]}",
            action="identity.root_disk_acknowledged",
            deployment_id=args.deployment_id,
            detail={"instance_id": args.instance_id},
        )
    print(json.dumps({"acknowledged": args.instance_id, "deployment_id": args.deployment_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
