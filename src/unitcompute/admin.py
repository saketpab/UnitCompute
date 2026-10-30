"""Operator commands: migrations, configuration checks and recovery reports."""

from __future__ import annotations

import argparse
import json
import re
import sys

from unitcompute.config import ConfigError, load_settings
from unitcompute.db.database import Database
from unitcompute.identities import OPERATOR_ROOT_VOLUME, IdentityLedger, identity
from unitcompute.logging_setup import secure_process_defaults
from unitcompute.provisioning.base import Provisioner, ProvisioningError
from unitcompute.provisioning.factory import build_provisioner
from unitcompute.services.deployments import record_audit

_DEPLOYMENT = re.compile(r"^dep_[0-9a-f]{32}$")
_INSTANCE = re.compile(r"^i-[0-9a-f]{8,17}$")
_VOLUME = re.compile(r"^vol-[0-9a-f]{8,17}$")


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
    record = sub.add_parser(
        "record-root-volume",
        help="record the identity of a known instance's root volume (AWS must confirm the "
        "volume exists; deletion then verifies it is gone like any other resource)",
    )
    record.add_argument("deployment_id")
    record.add_argument("instance_id")
    record.add_argument("volume_id")
    record.add_argument("--operator", required=True, help="who identified it (audited)")
    record.add_argument("--reason", required=True, help="how it was identified, e.g. CloudTrail")
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
    if args.command == "record-root-volume":
        provisioner = build_provisioner(settings)
        if provisioner is None:
            print("provisioning is disabled; AWS cannot confirm the volume", file=sys.stderr)
            return 2
        return _record_root_volume(db, args, provisioner, IdentityLedger(settings.workdir_root))
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


def _record_root_volume(
    db: Database, args: argparse.Namespace, provisioner: Provisioner, ledger: IdentityLedger
) -> int:
    """Add recoverable root-disk evidence. Never a waiver: the volume must exist now, and a
    later deletion only completes once AWS reports it gone."""
    if not (
        _DEPLOYMENT.fullmatch(args.deployment_id)
        and _INSTANCE.fullmatch(args.instance_id)
        and _VOLUME.fullmatch(args.volume_id)
    ):
        print("invalid deployment, instance or volume ID", file=sys.stderr)
        return 2
    if not args.operator.strip() or not args.reason.strip():
        print("operator and reason are required", file=sys.stderr)
        return 2
    with db.read() as conn:
        known = IdentityLedger.known(conn, args.deployment_id)
    if args.instance_id not in known.instances:
        print("that instance is not recorded for this deployment", file=sys.stderr)
        return 1
    try:
        mapped = provisioner.instance_volumes([args.instance_id]).get(args.instance_id, [])
        roots = [volume for volume, is_root in mapped if is_root]
        if roots and args.volume_id not in roots:
            print(
                f"AWS reports a different root volume for {args.instance_id}: {', '.join(roots)}",
                file=sys.stderr,
            )
            return 1
        exists = any(
            r.resource_id == args.volume_id for r in provisioner.find_resources([args.volume_id])
        )
    except ProvisioningError as exc:
        print(f"AWS lookup failed: {exc.safe_message}", file=sys.stderr)
        return 1
    if not exists:
        print(
            "AWS does not report that volume; only an existing volume can be recorded as "
            "evidence (absence must be proven by verification, not asserted)",
            file=sys.stderr,
        )
        return 1
    ledger.append_evidence(
        args.deployment_id,
        [identity(args.volume_id, OPERATOR_ROOT_VOLUME, args.instance_id)],
    )
    with db.transaction() as conn:
        ledger.import_evidence(conn, args.deployment_id)
        record_audit(
            conn,
            actor=f"operator:{args.operator[:100]}",
            action="identity.root_volume_recorded",
            deployment_id=args.deployment_id,
            detail={
                "instance_id": args.instance_id,
                "volume_id": args.volume_id,
                "reason": args.reason[:200],
            },
        )
    print(
        json.dumps(
            {
                "recorded_root_volume": args.volume_id,
                "instance_id": args.instance_id,
                "deployment_id": args.deployment_id,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
