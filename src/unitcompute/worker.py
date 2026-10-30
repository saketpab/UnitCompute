"""The single provisioning worker.

Exactly one worker runs per data directory, enforced by an exclusive ``flock`` that is
also inherited by every Terraform child process. Holding the lock therefore proves that
no earlier worker or Terraform process is still running, which is what makes recovery of
interrupted jobs safe.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import shutil
import signal
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import FrameType
from typing import Any

from unitcompute.config import ProvisionerKind, Settings, load_settings
from unitcompute.db.database import Connection, Database, Row, from_db_time, to_db_time, utcnow
from unitcompute.durable import ensure_directory
from unitcompute.errors import ServiceUnavailable
from unitcompute.identities import (
    ATTACHED_DEVICE,
    LAUNCH_OUTPUT,
    LAUNCH_STATE,
    ROOT_DEVICE,
    Identity,
    IdentityLedger,
    KnownIdentities,
    identity,
)
from unitcompute.logging_setup import configure_logging, redact, secure_process_defaults
from unitcompute.pricing import estimate_monthly_cost
from unitcompute.provisioning.base import (
    DeploymentSpec,
    NotStarted,
    OwnedResource,
    PlanKind,
    Provisioner,
    ProvisioningError,
    Readiness,
    dispatch_guard,
    owner_tag,
    sha256_file,
)
from unitcompute.provisioning.factory import build_provisioner
from unitcompute.provisioning.policy import (
    evaluate_plan,
    prior_resource_identities,
    prior_resource_ids,
)
from unitcompute.provisioning.state_evidence import (
    AppliedState,
    StateEvidenceError,
    bind_to_plan,
    observed_identities,
    parse_raw_state,
    read_state_file,
)
from unitcompute.services.deployments import (
    Clock,
    binding_problem,
    execution_binding,
    expected_versions,
    plan_expiry,
    plan_versions,
    record_audit,
    unresolved_create_obligation,
)

log = logging.getLogger(__name__)
ACTOR = "system:worker"
HEARTBEAT_SECONDS = 15
WRITE_RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0, 8.0)
_ID = re.compile(r"^(dep|plan)_[0-9a-f]{32}$")
ERRORED_STATE = "errored.tfstate"


def _missing_root_message(instances: list[str]) -> str:
    return (
        "The launch root disk of " + ", ".join(instances) + " was never recorded from the "
        "apply that launched it and may still exist. Refreshed state and current mappings "
        "cannot prove it, so repair and deletion stay blocked; this needs a support decision "
        "(see the operations guide)."
    )


def planned_changes(preview_json: str | None) -> list[dict[str, Any]] | None:
    """The plan's recorded resource changes, or None if they cannot be read exactly."""
    try:
        preview = json.loads(preview_json or "")
    except ValueError:
        return None
    changes = preview.get("changes") if isinstance(preview, dict) else None
    if not isinstance(changes, list) or not all(
        isinstance(c, dict) and isinstance(c.get("action"), str) for c in changes
    ):
        return None
    return changes


def planned_creates(plan: Row) -> set[str] | None:
    changes = planned_changes(plan["preview_json"])
    if changes is None:
        return None
    return {str(c.get("address")) for c in changes if c["action"] != "delete"}


def plan_launches_instance(plan: Row) -> bool:
    """True when this plan itself creates the VM, so its outputs/state name the launch root."""
    return any(
        c.get("address") == "aws_instance.vm" and c["action"] == "create"
        for c in planned_changes(plan["preview_json"]) or []
    )


def plan_may_create(plan: Row) -> bool:
    """False only when the recorded changes show the plan creates nothing (deletions only,
    or no changes at all). Unreadable or unknown changes count as creating."""
    creates = planned_creates(plan)
    return creates is None or bool(creates)


class WorkerLockHeld(RuntimeError):
    pass


class WorkerLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def acquire(self) -> int:
        ensure_directory(self.path.parent)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise WorkerLockHeld(
                "Another worker (or a Terraform process it started) still holds the lock."
            ) from exc
        self.fd = fd
        return fd

    def release(self) -> None:
        # Close rather than LOCK_UN: an explicit unlock would also drop the lock held via
        # the same open file description by any still-running Terraform child.
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class JobFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Worker:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        provisioner: Provisioner,
        clock: Clock = utcnow,
        worker_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.provisioner = provisioner
        self.clock = clock
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._stop = threading.Event()
        self._healthy = False
        self._checked_at: float | None = None
        self._registered = False
        self.write_retry_delays: tuple[float, ...] = WRITE_RETRY_DELAYS
        self.identities = IdentityLedger(settings.workdir_root)

    # ------------------------------------------------------------ lifecycle

    def stop(self) -> None:
        self._stop.set()

    def register(self) -> None:
        now = to_db_time(self.clock())
        with self._tx() as conn:
            conn.execute(
                (
                    "INSERT INTO worker_heartbeats (worker_id, started_at, heartbeat_at, "
                    "healthy, checks_json) VALUES (%s, %s, %s, 0, '{}') ON CONFLICT (worker_id) "
                    "DO UPDATE SET started_at=EXCLUDED.started_at, "
                    "heartbeat_at=EXCLUDED.heartbeat_at, healthy=0, checks_json='{}'"
                ),
                (self.worker_id, now, now),
            )
        self._registered = True

    def _self_check_due(self) -> bool:
        return self._checked_at is None or (
            time.monotonic() - self._checked_at >= self.settings.worker_self_check_seconds
        )

    def self_check(self) -> bool:
        """Verify Terraform and the AWS execution identities before taking work."""
        try:
            checks: dict[str, Any] = {"ok": True, **self.provisioner.self_check()}
        except ProvisioningError as exc:
            checks = {"ok": False, "code": exc.code, "message": exc.safe_message}
        except Exception:
            log.exception("worker self-check crashed")
            checks = {"ok": False, "code": "internal_error", "message": "Self-check failed."}
        self._healthy = bool(checks["ok"])
        self._checked_at = time.monotonic()
        if not self._registered:
            self.register()
        with self._tx() as conn:
            conn.execute(
                "UPDATE worker_heartbeats SET healthy = %s, checks_json = %s, heartbeat_at = %s "
                "WHERE worker_id = %s",
                (
                    int(self._healthy),
                    json.dumps(checks, default=str),
                    to_db_time(self.clock()),
                    self.worker_id,
                ),
            )
        if not self._healthy:
            log.error("worker self-check failed; not taking jobs", extra={"fields": checks})
        return self._healthy

    @contextmanager
    def _tx(self) -> Iterator[Connection]:
        """Write transaction that retries lock acquisition before giving up."""
        delays = [*self.write_retry_delays, None]
        for delay in delays:
            context = self.db.transaction()
            try:
                conn = context.__enter__()
            except ServiceUnavailable:
                if delay is None:
                    raise
                time.sleep(delay)
                continue
            break
        try:
            yield conn
        except BaseException as exc:
            context.__exit__(type(exc), exc, exc.__traceback__)
            raise
        context.__exit__(None, None, None)

    def recover_interrupted(self) -> list[str]:
        """Call only while holding the worker lock: any 'running' job is orphaned.

        Each job is recovered on its own; a problem with one deployment's evidence never
        stops recovery (or service) for the others."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
                "ON plans.id = jobs.plan_id WHERE jobs.status = 'running'"
            ).fetchall()
        recovered: list[str] = []
        for job in rows:
            recovered.append(job["id"])
            try:
                self.import_identities(job["deployment_id"])
            except Exception:
                # Not proof of corruption (a lock wait or database error is transient); only
                # invalid records open an evidence_file_corrupt obligation. The apply's own
                # obligation below still keeps the deployment fail-closed.
                log.exception(
                    "evidence import failed during recovery",
                    extra={"fields": {"deployment_id": job["deployment_id"]}},
                )
            if job["kind"] == "plan":
                with self._tx() as conn:
                    self._finish_plan_failure(
                        conn,
                        job,
                        "worker_interrupted",
                        "Planning was interrupted; request a new preview.",
                    )
                continue
            self._recovery_required(
                job,
                "worker_interrupted",
                "The worker stopped while applying. AWS may hold partially created or "
                "deleted resources; request a new preview to reconcile.",
                immediate=False,
            )
        return recovered

    def run_forever(self) -> None:
        self.register()
        self.recover_interrupted()
        while not self._stop.is_set():
            try:
                worked = self.run_once()
                self.housekeeping()
            except Exception:
                log.exception("worker iteration failed")
                worked = False
            if not worked:
                self._stop.wait(self.settings.worker_poll_seconds)

    # ----------------------------------------------------------------- jobs

    def claim(self) -> Row | None:
        now = to_db_time(self.clock())
        with self._tx() as conn:
            job = conn.execute(
                "SELECT * FROM jobs WHERE status = 'queued' ORDER BY sequence FOR "
                "UPDATE SKIP LOCKED LIMIT 1"
            ).fetchone()
            if job is None:
                return None
            conn.execute(
                "UPDATE jobs SET status = 'running', worker_id = %s, started_at = %s, "
                "heartbeat_at = %s WHERE id = %s AND status = 'queued'",
                (self.worker_id, now, now, job["id"]),
            )
            row = conn.execute(
                "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
                "ON plans.id = jobs.plan_id WHERE jobs.id = %s",
                (job["id"],),
            ).fetchone()
            return row

    def run_once(self) -> bool:
        # While this worker holds the lock and is between jobs, any 'running' job is
        # stranded (for example its completion could not be persisted). Recover it before
        # taking new work; it is never re-applied.
        if self._has_stranded_jobs():
            self.recover_interrupted()
        if self._self_check_due() and not self.self_check():
            return False
        if not self._healthy:
            return False
        job = self.claim()
        if job is None:
            return False
        stop_heartbeat = threading.Event()
        beat = threading.Thread(
            target=self._heartbeat, args=(job["id"], stop_heartbeat), daemon=True
        )
        beat.start()
        try:
            if job["kind"] == "plan":
                self.process_plan(job)
            else:
                self.process_apply(job)
        except Exception:
            # Never leave a claimed job 'running' behind a live worker.
            log.exception("job processing crashed", extra={"fields": {"job_id": job["id"]}})
            self._finish_crashed(job)
        finally:
            stop_heartbeat.set()
            beat.join(timeout=5)
        return True

    def _has_stranded_jobs(self) -> bool:
        with self.db.read() as conn:
            return (
                conn.execute("SELECT 1 FROM jobs WHERE status = 'running' LIMIT 1").fetchone()
                is not None
            )

    def _finish_crashed(self, job: Row) -> None:
        with self.db.read() as conn:
            current = conn.execute("SELECT status FROM jobs WHERE id = %s", (job["id"],)).fetchone()
        if current is None or current["status"] != "running":
            return
        if job["kind"] == "plan":
            with self._tx() as conn:
                self._finish_plan_failure(
                    conn,
                    job,
                    "internal_error",
                    "Planning failed unexpectedly; request a new preview.",
                )
        else:
            self._recovery_required(
                job, "internal_error", "Apply processing failed unexpectedly.", immediate=False
            )

    def _heartbeat(self, job_id: str, stop: threading.Event) -> None:
        while not stop.wait(HEARTBEAT_SECONDS):
            try:
                now = to_db_time(self.clock())
                with self.db.transaction() as conn:
                    conn.execute("UPDATE jobs SET heartbeat_at = %s WHERE id = %s", (now, job_id))
                    conn.execute(
                        "UPDATE worker_heartbeats SET heartbeat_at = %s WHERE worker_id = %s",
                        (now, self.worker_id),
                    )
            except Exception:
                log.warning("heartbeat update failed", exc_info=True)

    def _load(self, job: Row) -> tuple[Row, Row]:
        with self.db.read() as conn:
            deployment = conn.execute(
                "SELECT * FROM deployments WHERE id = %s", (job["deployment_id"],)
            ).fetchone()
            plan = conn.execute("SELECT * FROM plans WHERE id = %s", (job["plan_id"],)).fetchone()
        if deployment is None or plan is None:
            raise RuntimeError("job references missing deployment or plan")
        return deployment, plan

    @staticmethod
    def _spec(deployment: Row) -> DeploymentSpec:
        return DeploymentSpec(
            deployment_id=deployment["id"],
            owner_tag=owner_tag(deployment["cloud_owner_id"]),
            name=deployment["name"],
            disk_gib=deployment["disk_gib"],
            region=deployment["region"],
            instance_type=deployment["instance_type"],
        )

    def workdir(self, deployment_id: str, plan_id: str) -> Path:
        if not (_ID.fullmatch(deployment_id) and _ID.fullmatch(plan_id)):
            raise JobFailure("invalid_identifier", "Invalid deployment or plan identifier.")
        ensure_directory(self.settings.workdir_root)
        root = self.settings.workdir_root.resolve()
        path = (root / deployment_id / plan_id).resolve()
        if not path.is_relative_to(root):
            raise JobFailure("invalid_identifier", "Invalid work directory.")
        ensure_directory(path.parent)
        return path

    def _finish_plan_failure(
        self,
        conn: Connection,
        job: Row,
        code: str,
        message: str,
        plan_status: str = "failed",
    ) -> None:
        now = to_db_time(self.clock())
        message = redact(message)[:2000]
        conn.execute(
            "UPDATE jobs SET status = 'failed', finished_at = %s, error_code = %s, "
            "error_message = %s WHERE id = %s",
            (now, code, message, job["id"]),
        )
        conn.execute(
            "UPDATE plans SET status = %s, error_code = %s, error_message = %s "
            "WHERE id = %s AND status IN ('pending', 'approved')",
            (plan_status, code, message, job["plan_id"]),
        )
        # A deployment whose last apply needs recovery stays recovery_required until a later
        # apply succeeds, so a failed repair preview cannot hide partial resources.
        unresolved = conn.execute(
            "SELECT status FROM jobs WHERE deployment_id = %s AND kind = 'apply' "
            "ORDER BY sequence DESC LIMIT 1",
            (job["deployment_id"],),
        ).fetchone()
        open_uncaptured = conn.execute(
            "SELECT 1 FROM recovery_obligations WHERE deployment_id = %s "
            "AND discharged_at IS NULL AND evidence = 'uncaptured' LIMIT 1",
            (job["deployment_id"],),
        ).fetchone()
        status = (
            "recovery_required"
            if open_uncaptured is not None
            or (unresolved is not None and unresolved["status"] == "recovery_required")
            else "plan_failed"
        )
        conn.execute(
            "UPDATE deployments SET status = %s, status_reason = %s, updated_at = %s "
            "WHERE id = %s AND current_plan_id = %s",
            (status, message, now, job["deployment_id"], job["plan_id"]),
        )
        record_audit(
            conn,
            actor=ACTOR,
            action="plan.failed",
            deployment_id=job["deployment_id"],
            plan_id=job["plan_id"],
            job_id=job["id"],
            detail={"code": code},
        )

    def process_plan(self, job: Row) -> None:
        deployment, plan = self._load(job)
        kind: PlanKind = plan["kind"]
        try:
            if plan["status"] != "pending" or deployment["current_plan_id"] != plan["id"]:
                raise JobFailure("plan_superseded", "A newer plan replaced this one.")
            spec = self._spec(deployment)
            self._retry_uncaptured(deployment["id"])
            owner = deployment["owner_id"] if kind == "create" else None
            self._require_no_uncaptured(deployment["id"], owner)
            frozen_ami = deployment["ami_id"] if deployment["apply_attempted"] else None
            result = self.provisioner.plan(
                spec, kind, self.workdir(spec.deployment_id, plan["id"]), frozen_ami
            )
            actual = {
                "template_version": result.versions.template_version,
                "template_hash": result.versions.template_hash,
                "terraform_version": result.versions.terraform_version,
                "provider_versions": result.versions.provider_versions,
            }
            if actual != expected_versions(self.provisioner.kind):
                raise JobFailure("plan_stale", "Tool or template versions changed; retry.")
            inventory = self._reconciled_inventory(spec.deployment_id, result.plan_json)
            # Reconciliation can itself open an obligation (e.g. a corrupt evidence record);
            # it must stop this plan, not just later ones.
            self._require_no_uncaptured(deployment["id"])
            policy = evaluate_plan(
                result.plan_json,
                kind=kind,
                spec=spec,
                targets=self.provisioner.network_targets(),
                ami_id=result.ami_id,
                inventory=inventory,
            )
        except JobFailure as exc:
            with self._tx() as conn:
                self._finish_plan_failure(conn, job, exc.code, exc.message)
            return
        except ProvisioningError as exc:
            log.warning("plan failed", extra={"fields": {"job_id": job["id"], "code": exc.code}})
            with self._tx() as conn:
                self._finish_plan_failure(conn, job, exc.code, exc.safe_message)
            return
        except Exception:
            log.exception("unexpected planning failure", extra={"fields": {"job_id": job["id"]}})
            with self._tx() as conn:
                self._finish_plan_failure(
                    conn,
                    job,
                    "internal_error",
                    "Planning failed unexpectedly; an operator was notified.",
                )
            return

        now_dt = self.clock()
        now = to_db_time(now_dt)
        with self._tx() as conn:
            if not policy.allowed:
                self._finish_plan_failure(
                    conn,
                    job,
                    "policy_violation",
                    "The plan was rejected by policy: " + "; ".join(policy.violations),
                    plan_status="rejected",
                )
                return
            cost = estimate_monthly_cost(spec.disk_gib).model_dump() if kind == "create" else None
            warnings = list(policy.warnings)
            if kind == "destroy":
                warnings.append("Deleting stops this VM's ongoing compute, IPv4 and disk charges.")
            if self.provisioner.kind == ProvisionerKind.SIMULATED:
                warnings.append("SIMULATED: no AWS resources are created or deleted.")
            updated = conn.execute(
                "UPDATE plans SET status = 'ready', plan_hash = %s, plan_path = %s, "
                "preview_json = %s, cost_json = %s, template_hash = %s, terraform_version = %s, "
                "provider_versions_json = %s, account_id = %s, ami_id = %s, ready_at = %s, "
                "expires_at = %s, execution_hash = %s, prior_resource_ids_json = %s "
                "WHERE id = %s AND status = 'pending'",
                (
                    result.plan_hash,
                    str(result.plan_path),
                    json.dumps({"changes": policy.changes, "warnings": warnings}),
                    json.dumps(cost) if cost else None,
                    actual["template_hash"],
                    actual["terraform_version"],
                    json.dumps(actual["provider_versions"], sort_keys=True),
                    result.account_id,
                    result.ami_id,
                    now,
                    to_db_time(plan_expiry(now_dt, self.settings)),
                    execution_binding(self.settings, deployment["id"]),
                    json.dumps(sorted(prior_resource_ids(result.plan_json))),
                    plan["id"],
                ),
            ).rowcount
            if updated != 1:
                self._finish_plan_failure(
                    conn, job, "plan_superseded", "A newer plan replaced this one."
                )
                return
            status = "awaiting_approval" if kind == "create" else "awaiting_deletion_approval"
            conn.execute(
                "UPDATE deployments SET status = %s, status_reason = NULL, updated_at = %s "
                "WHERE id = %s AND current_plan_id = %s",
                (status, now, deployment["id"], plan["id"]),
            )
            conn.execute(
                "UPDATE jobs SET status = 'succeeded', finished_at = %s, result_json = %s "
                "WHERE id = %s",
                (
                    now,
                    json.dumps({"plan_id": plan["id"], "plan_hash": result.plan_hash}),
                    job["id"],
                ),
            )
            record_audit(
                conn,
                actor=ACTOR,
                action="plan.ready",
                deployment_id=deployment["id"],
                plan_id=plan["id"],
                job_id=job["id"],
                detail={"kind": kind, "plan_hash": result.plan_hash},
            )

    # ------------------------------------------------------------ identities

    def record_identities(self, deployment_id: str, identities: list[Identity | None]) -> None:
        """Durably append identity evidence (file first, then the append-only table)."""
        if not self.identities.append_evidence(deployment_id, identities):
            return
        with self._tx() as conn:
            imported = self.identities.import_evidence(conn, deployment_id)
            absent = self.identities.missing(conn, deployment_id, identities)
        if imported.corrupt:
            self._open_obligation(deployment_id, None, None, "evidence_file_corrupt", "uncaptured")
        if absent:
            # Never report evidence as recorded unless the exact rows are present.
            raise RuntimeError(
                "identity evidence not present after import: "
                + ", ".join(f"{i.resource_id}/{i.source}" for i in absent)
            )

    def import_identities(self, deployment_id: str) -> KnownIdentities:
        with self._tx() as conn:
            imported = self.identities.import_evidence(conn, deployment_id)
            known = self.identities.known(conn, deployment_id)
        if imported.corrupt:
            self._open_obligation(deployment_id, None, None, "evidence_file_corrupt", "uncaptured")
        return known

    def _discover_volumes(self, deployment_id: str, instance_ids: list[str]) -> None:
        if not instance_ids:
            return
        mapped = self.provisioner.instance_volumes(instance_ids)
        self.record_identities(
            deployment_id,
            [
                identity(volume, ROOT_DEVICE if is_root else ATTACHED_DEVICE, instance_id)
                for instance_id, volumes in mapped.items()
                for volume, is_root in volumes
            ],
        )

    def _reconciled_inventory(
        self, deployment_id: str, plan_json: dict[str, Any]
    ) -> list[OwnedResource]:
        """Everything that exists for this deployment: tagged, or known from any evidence.

        Anything here that Terraform state does not contain is an orphan and blocks the plan,
        so a lost state or removed tag can never lead to a second VM."""
        self.record_identities(
            deployment_id,
            [
                identity(rid, "terraform_state", parent)
                for rid, parent in prior_resource_identities(plan_json)
            ],
        )
        tagged = self.provisioner.owned_resources(deployment_id)
        self.record_identities(
            deployment_id, [identity(r.resource_id, "tag_inventory") for r in tagged]
        )
        known = self.import_identities(deployment_id)
        live = self.provisioner.find_resources(known.all_ids)
        self._discover_volumes(
            deployment_id, [r.resource_id for r in live if r.resource_type == "instance"]
        )
        known = self.import_identities(deployment_id)
        missing = known.instances_without_root_disk()
        if missing:
            # A known instance whose root disk was never identified may have left a billable
            # disk behind; neither repair nor deletion may proceed until it is identified.
            raise JobFailure("identity_incomplete", _missing_root_message(missing))
        # Look up again: disks discovered just now (e.g. a replacement root) must also be
        # reconciled against Terraform state in this same plan.
        live = self.provisioner.find_resources(known.all_ids)
        merged = {r.resource_id: r for r in [*tagged, *live]}
        return list(merged.values())

    def _precheck_apply(self, job: Row, deployment: Row, plan: Row) -> Path:
        if (
            plan["status"] != "approved"
            or deployment["current_plan_id"] != plan["id"]
            or not (
                job["owner_id"] == deployment["owner_id"] == plan["owner_id"] == plan["approved_by"]
            )
        ):
            raise JobFailure("plan_not_approved", "The plan is no longer the approved plan.")
        expected_status = "applying" if plan["kind"] == "create" else "deleting"
        if deployment["status"] != expected_status:
            raise JobFailure("invalid_state", "The deployment is not awaiting this apply.")
        expected = expected_versions(self.provisioner.kind)
        runtime = self.provisioner.runtime_versions()
        actual = {
            "template_version": runtime.template_version,
            "template_hash": runtime.template_hash,
            "terraform_version": runtime.terraform_version,
            "provider_versions": runtime.provider_versions,
        }
        if plan_versions(plan) != expected or actual != expected:
            raise JobFailure("plan_stale", "Tool or template versions changed since approval.")
        binding = binding_problem(self.settings, plan)
        if binding:
            raise JobFailure("plan_stale", binding)
        workdir = self.workdir(deployment["id"], plan["id"])
        plan_path = Path(plan["plan_path"] or "")
        if plan_path.resolve() != (workdir / "tfplan").resolve() or not plan_path.is_file():
            raise JobFailure("plan_missing", "The saved plan file is missing.")
        if sha256_file(plan_path) != plan["plan_hash"]:
            raise JobFailure("plan_hash_mismatch", "The saved plan changed after approval.")
        if (workdir / ERRORED_STATE).exists():
            # Any errored.tfstate found after the apply must be that apply's own.
            raise JobFailure("plan_tampered", "The plan's work directory holds unexpected state.")
        # Immediately before mutating: reconcile evidence, then re-check obligations, so an
        # obligation opened since the plan was made (or by this import) stops the apply.
        try:
            self.import_identities(deployment["id"])
        except Exception as exc:
            log.warning("evidence import failed before apply", exc_info=True)
            raise JobFailure(
                "evidence_unavailable", "Identity evidence could not be read; retry later."
            ) from exc
        owner = deployment["owner_id"] if plan["kind"] == "create" else None
        self._require_no_uncaptured(deployment["id"], owner)
        return plan_path

    def _require_unexpired(self, plan: Row) -> None:
        if from_db_time(plan["expires_at"]) <= self.clock():
            raise JobFailure(
                "plan_expired",
                "The approved plan expired before it could run; "
                "request a fresh preview and approve it.",
            )

    def _refuse_expired_dispatch(self, plan: Row) -> None:
        """Installed as the dispatch guard: called by the provisioner immediately before a
        mutating process is spawned, after its own blocking preparation."""
        try:
            self._require_unexpired(plan)
        except JobFailure as exc:
            raise NotStarted(exc.code, exc.message) from exc

    def process_apply(self, job: Row) -> None:
        deployment, plan = self._load(job)
        spec = self._spec(deployment)
        try:
            plan_path = self._precheck_apply(job, deployment, plan)
            with self._tx() as conn:
                # The precheck can block (evidence lock, database retries); judge expiry again
                # now that the write lock is held, before recording that an apply starts.
                self._require_unexpired(plan)
                conn.execute(
                    "UPDATE deployments SET apply_attempted = 1, "
                    "ami_id = COALESCE(%s, ami_id), updated_at = %s WHERE id = %s",
                    (
                        plan["ami_id"] if plan["kind"] == "create" else None,
                        to_db_time(self.clock()),
                        deployment["id"],
                    ),
                )
                record_audit(
                    conn,
                    actor=ACTOR,
                    action="apply.started",
                    deployment_id=deployment["id"],
                    plan_id=plan["id"],
                    job_id=job["id"],
                    detail={"kind": plan["kind"], "plan_hash": plan["plan_hash"]},
                )
            self._require_unexpired(plan)  # and once more immediately before dispatch
        except (JobFailure, ProvisioningError) as exc:
            code = exc.code
            message = exc.message if isinstance(exc, JobFailure) else exc.safe_message
            with self._tx() as conn:
                self._finish_plan_failure(conn, job, code, message)
            return

        try:
            with dispatch_guard(lambda: self._refuse_expired_dispatch(plan)):
                outcome = self.provisioner.apply(spec, plan_path.parent, plan_path)
            # Persist returned identities before anything else can fail. The root output is
            # launch evidence only if this apply created the instance.
            instance_output = outcome.outputs.get("instance_id")
            launched = plan_launches_instance(plan)
            self.record_identities(
                spec.deployment_id,
                [
                    identity(instance_output, "apply_output_seen"),
                    identity(outcome.outputs.get("security_group_id"), "apply_output_seen"),
                    identity(
                        outcome.outputs.get("root_volume_id"),
                        LAUNCH_OUTPUT if launched else "apply_output_seen",
                        instance_output,
                    ),
                ],
            )
            inventory = self.provisioner.owned_resources(spec.deployment_id)
            self.record_identities(
                spec.deployment_id,
                [identity(r.resource_id, "tag_inventory") for r in inventory],
            )
        except NotStarted as exc:
            # Refused at the dispatch boundary: no process ran, so there is nothing to recover.
            with self._tx() as conn:
                self._finish_plan_failure(conn, job, exc.code, exc.safe_message)
            return
        except ProvisioningError as exc:
            # Whatever the exit (error, signal, timeout), the outcome is established only by
            # bound evidence; see _capture_apply_evidence.
            self._recovery_required(job, exc.code, exc.safe_message)
            return
        except Exception:
            log.exception("unexpected apply failure", extra={"fields": {"job_id": job["id"]}})
            self._recovery_required(job, "internal_error", "Apply failed unexpectedly.")
            return

        now = to_db_time(self.clock())
        result: dict[str, Any] = {"plan_id": plan["id"], "kind": plan["kind"]}
        if plan["kind"] == "create":
            instance_id = outcome.outputs.get("instance_id")
            try:
                found = self.provisioner.find_resources([instance_id]) if instance_id else []
            except ProvisioningError as exc:
                self._recovery_required(job, exc.code, exc.safe_message)
                return
            if (
                not instance_id
                or not any(r.resource_id == instance_id for r in inventory)
                or not any(r.resource_id == instance_id for r in found)
            ):
                self._recovery_required(
                    job, "verification_failed", "Apply finished but the VM could not be verified."
                )
                return
            result.update(instance_id=instance_id)
            with self._tx() as conn:
                conn.execute(
                    "UPDATE deployments SET status = 'active', status_reason = NULL, "
                    "instance_id = %s, security_group_id = %s, "
                    "root_volume_id = CASE WHEN %s <> 0 THEN %s ELSE root_volume_id END, "
                    "connection_ready = 0, ec2_status = NULL, ssm_ping_status = NULL, "
                    "readiness_checked_at = NULL, updated_at = %s WHERE id = %s",
                    (
                        instance_id,
                        outcome.outputs.get("security_group_id"),
                        int(plan_launches_instance(plan)),
                        outcome.outputs.get("root_volume_id"),
                        now,
                        deployment["id"],
                    ),
                )
                self._finish_apply_success(conn, job, plan, result, "deployment.active")
            # Infrastructure is applied and verified; connection readiness is observed
            # separately (bounded here, then refreshed by housekeeping).
            self.observe_readiness(deployment["id"], instance_id, wait=True)
            return

        remaining = self._remaining_after_delete(deployment, plan, inventory)
        if isinstance(remaining, JobFailure):
            self._recovery_required(job, remaining.code, remaining.message)
            return
        if remaining:
            self._recovery_required(
                job,
                "resources_remaining",
                "Delete ran but owned resources still exist: " + ", ".join(remaining),
            )
            return
        if self._uncaptured_obligations(deployment["id"]):
            self._recovery_required(
                job,
                "recovery_evidence_missing",
                "An earlier failed apply's evidence was never captured; deletion cannot be "
                "verified.",
            )
            return
        with self._tx() as conn:
            conn.execute(
                "UPDATE deployments SET status = 'deleted', status_reason = NULL, "
                "connection_ready = 0, ssm_ping_status = NULL, ec2_status = NULL, "
                "updated_at = %s WHERE id = %s",
                (now, deployment["id"]),
            )
            self._finish_apply_success(conn, job, plan, result, "deployment.deleted")

    def _remaining_after_delete(
        self, deployment: Row, plan: Row, inventory: list[OwnedResource]
    ) -> list[str] | JobFailure:
        """Every identity ever recorded must be confirmed gone by direct lookup.

        Returns a JobFailure when absence cannot be established: a lookup failed, or a known
        instance's root disk was never identified (its mapping disappears on termination).
        The deployment then keeps its recovery status and quota slot."""
        try:
            known = self.import_identities(deployment["id"])
            live = self.provisioner.find_resources(known.all_ids)
            self._discover_volumes(
                deployment["id"], [r.resource_id for r in live if r.resource_type == "instance"]
            )
            known = self.import_identities(deployment["id"])
            missing_disks = known.instances_without_root_disk()
            if missing_disks:
                return JobFailure("identity_incomplete", _missing_root_message(missing_disks))
            found = self.provisioner.find_resources(known.all_ids)
        except ProvisioningError:
            log.warning("deletion verification failed", exc_info=True)
            return JobFailure(
                "verification_failed",
                "Delete ran but it could not be verified that the VM, disk and security group "
                "are gone.",
            )
        remaining = {f"{r.resource_type}:{r.resource_id}" for r in [*inventory, *found]}
        return sorted(remaining)

    def _finish_apply_success(
        self,
        conn: Connection,
        job: Row,
        plan: Row,
        result: dict[str, Any],
        action: str,
    ) -> None:
        now = to_db_time(self.clock())
        conn.execute("UPDATE plans SET status = 'applied' WHERE id = %s", (plan["id"],))
        # A verified apply discharges obligations whose evidence was captured (and so was
        # reconciled by this plan). Uncaptured ones can never be discharged this way.
        conn.execute(
            "UPDATE recovery_obligations SET discharged_at = %s, discharged_by_job_id = %s "
            "WHERE deployment_id = %s AND discharged_at IS NULL "
            "AND evidence IN ('captured', 'not_needed')",
            (now, job["id"], job["deployment_id"]),
        )
        conn.execute(
            (
                "UPDATE jobs SET status = 'succeeded', finished_at = %s, "
                "result_json = %s WHERE id = %s"
            ),
            (now, json.dumps(result), job["id"]),
        )
        record_audit(
            conn,
            actor=ACTOR,
            action=action,
            deployment_id=job["deployment_id"],
            plan_id=plan["id"],
            job_id=job["id"],
        )

    def _capture_apply_evidence(self, job: Row, *, immediate: bool) -> str:
        """Establish what a failed apply did. Returns the obligation's evidence state.

        Accepted evidence is a validated raw state bound to this apply's saved plan (see
        ``state_evidence``): ``errored.tfstate`` from the plan's work directory (Terraform's
        final state when the backend write failed) or, only right after the apply
        (``immediate``) and only if this is still the latest apply, the stored state, which
        must then show every resource the plan creates. A process exit, normal or by
        signal, proves nothing by itself. IDs in any state read are recorded as
        observations even when it is not accepted. Otherwise: 'uncaptured' if the plan
        could create resources, else 'not_needed'."""
        deployment, plan = self._load(job)
        fallback = "uncaptured" if plan_may_create(plan) else "not_needed"
        workdir = self.settings.workdir_root / deployment["id"] / plan["id"]
        errored = workdir / ERRORED_STATE
        try:
            if errored.is_file():
                document, source, complete = read_state_file(errored), "errored_state", False
            elif immediate and self._is_latest_apply(job) and workdir.is_dir():
                document = self.provisioner.capture_stored_state(self._spec(deployment), workdir)
                source, complete = "stored_state", True
            else:
                return fallback
            self.record_identities(
                deployment["id"],
                [
                    identity(rid, f"{source}_seen", parent)
                    for rid, parent in observed_identities(document)
                ],
            )
            applied = self._bind_evidence(plan, workdir, document, require_all_creates=complete)
        except (StateEvidenceError, OSError, ProvisioningError):
            log.warning(
                "failed apply evidence not accepted",
                exc_info=True,
                extra={"fields": {"job_id": job["id"]}},
            )
            return fallback
        self.record_identities(
            deployment["id"],
            [
                identity(applied.instance_id, source),
                identity(applied.security_group_id, source),
                identity(
                    applied.root_volume_id,
                    LAUNCH_STATE if plan_launches_instance(plan) else f"{source}_seen",
                    applied.instance_id,
                ),
            ],
        )
        return "captured"

    def _bind_evidence(
        self, plan: Row, workdir: Path, document: object, *, require_all_creates: bool
    ) -> AppliedState:
        creates = planned_creates(plan)
        if creates is None:
            raise StateEvidenceError("the plan's changes are not recorded")
        plan_path = workdir / "tfplan"
        if not plan_path.is_file() or sha256_file(plan_path) != plan["plan_hash"]:
            raise StateEvidenceError("the applied saved plan is missing or changed")
        prior_ids = json.loads(plan["prior_resource_ids_json"] or "null")
        if not isinstance(prior_ids, list):
            raise StateEvidenceError("the plan's prior resource IDs are not recorded")
        parsed = parse_raw_state(document, terraform_version=str(plan["terraform_version"]))
        return bind_to_plan(
            parsed,
            prior=self.provisioner.prior_state(plan_path),
            prior_ids=set(prior_ids),
            creates=creates,
            require_all_creates=require_all_creates,
        )

    def _is_latest_apply(self, job: Row) -> bool:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT id FROM jobs WHERE deployment_id = %s AND kind = 'apply' "
                "ORDER BY sequence DESC LIMIT 1",
                (job["deployment_id"],),
            ).fetchone()
        return row is not None and row["id"] == job["id"]

    def _open_obligation(
        self,
        deployment_id: str,
        job_id: str | None,
        plan_id: str | None,
        reason: str,
        evidence: str,
    ) -> None:
        with self._tx() as conn:
            if (
                job_id is None
                and conn.execute(
                    "SELECT 1 FROM recovery_obligations WHERE deployment_id = %s AND reason = %s "
                    "AND discharged_at IS NULL",
                    (deployment_id, reason),
                ).fetchone()
            ):
                return
            conn.execute(
                "INSERT INTO recovery_obligations (deployment_id, job_id, plan_id, reason, "
                "evidence, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (deployment_id, job_id, plan_id, reason, evidence, to_db_time(self.clock())),
            )

    def _require_no_uncaptured(self, deployment_id: str, owner_id: str | None = None) -> None:
        """Own obligations block everything for the deployment. With ``owner_id`` (work that
        creates or repairs) an unproven apply of any of the owner's deployments blocks too,
        including a newer deployment that was reserved before the obligation existed.
        Cleanup (deletion) passes no owner, so it is never blocked by someone else's."""
        blocked = bool(self._uncaptured_obligations(deployment_id))
        if not blocked and owner_id is not None:
            with self.db.read() as conn:
                blocked = unresolved_create_obligation(conn, owner_id) is not None
        if blocked:
            raise JobFailure(
                "recovery_evidence_missing",
                "An earlier apply may have changed AWS, and what it did could not be "
                "established from state bound to that apply (or an evidence record is "
                "corrupt). Plans, applies and verified deletion stay blocked; this needs a "
                "support decision.",
            )

    def _uncaptured_obligations(self, deployment_id: str) -> list[Row]:
        with self.db.read() as conn:
            return list(
                conn.execute(
                    "SELECT * FROM recovery_obligations WHERE deployment_id = %s "
                    "AND discharged_at IS NULL AND evidence = 'uncaptured' ORDER BY id",
                    (deployment_id,),
                ).fetchall()
            )

    def _retry_uncaptured(self, deployment_id: str) -> None:
        """Try again to capture evidence for open obligations (e.g. migrated ones)."""
        for obligation in self._uncaptured_obligations(deployment_id):
            if not obligation["job_id"]:
                continue  # e.g. a corrupt evidence file: nothing to capture from
            with self.db.read() as conn:
                job = conn.execute(
                    "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
                    "ON plans.id = jobs.plan_id WHERE jobs.id = %s",
                    (obligation["job_id"],),
                ).fetchone()
            if job is None:
                continue
            evidence = self._capture_apply_evidence(job, immediate=False)
            if evidence == "uncaptured":
                continue
            with self._tx() as conn:
                conn.execute(
                    "UPDATE recovery_obligations SET evidence = %s WHERE id = %s",
                    (evidence, obligation["id"]),
                )

    def _recovery_required(
        self, job: Row, code: str, message: str, *, immediate: bool = True
    ) -> None:
        """``immediate``: called right after this worker ran the apply, so stored state can
        still be attributed to it. False after a crash or restart."""
        try:
            evidence = self._capture_apply_evidence(job, immediate=immediate)
        except Exception:
            log.exception("evidence capture crashed", extra={"fields": {"job_id": job["id"]}})
            evidence = "uncaptured"
        self._open_obligation(job["deployment_id"], job["id"], job["plan_id"], code, evidence)
        message = redact(message)[:2000]
        now = to_db_time(self.clock())
        reason = (
            f"{message} AWS may hold partially changed resources; request a new preview "
            "to reconcile. Resources that cannot be reconciled need an operator."
        )
        with self._tx() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'recovery_required', finished_at = %s, error_code = %s, "
                "error_message = %s WHERE id = %s",
                (now, code, message, job["id"]),
            )
            conn.execute(
                "UPDATE plans SET status = 'apply_failed', error_code = %s, "
                "error_message = %s WHERE id = %s",
                (code, message, job["plan_id"]),
            )
            conn.execute(
                "UPDATE deployments SET status = 'recovery_required', status_reason = %s, "
                "updated_at = %s WHERE id = %s",
                (reason, now, job["deployment_id"]),
            )
            record_audit(
                conn,
                actor=ACTOR,
                action="job.recovery_required",
                deployment_id=job["deployment_id"],
                plan_id=job["plan_id"],
                job_id=job["id"],
                detail={"code": code},
            )

    # ------------------------------------------------------------ readiness

    def observe_readiness(self, deployment_id: str, instance_id: str, *, wait: bool) -> bool:
        """Record EC2 status checks and SSM registration; optionally poll, bounded."""
        deadline = time.monotonic() + (self.settings.readiness_timeout_seconds if wait else 0)
        while True:
            try:
                readiness = self.provisioner.connection_readiness(instance_id)
            except Exception:
                log.warning("readiness lookup failed", exc_info=True)
                readiness = Readiness(ec2_status=None, ssm_status=None)
            with self._tx() as conn:
                conn.execute(
                    "UPDATE deployments SET ec2_status = %s, ssm_ping_status = %s, "
                    "connection_ready = %s, readiness_checked_at = %s "
                    "WHERE id = %s AND instance_id = %s AND status <> 'deleted'",
                    (
                        readiness.ec2_status,
                        readiness.ssm_status,
                        int(readiness.ready),
                        to_db_time(self.clock()),
                        deployment_id,
                        instance_id,
                    ),
                )
            if readiness.ready or time.monotonic() >= deadline or self._stop.is_set():
                return readiness.ready
            self._stop.wait(self.settings.readiness_poll_seconds)

    def refresh_readiness(self, limit: int = 5) -> int:
        cutoff = to_db_time(
            self.clock() - timedelta(seconds=self.settings.readiness_refresh_seconds)
        )
        with self.db.read() as conn:
            rows = conn.execute(
                # A launched VM may exist in every status except deleted, so a pending preview
                # never freezes a stale readiness answer.
                "SELECT id, instance_id FROM deployments WHERE status <> 'deleted' "
                "AND instance_id IS NOT NULL AND (readiness_checked_at IS NULL "
                "OR readiness_checked_at <= %s) ORDER BY readiness_checked_at LIMIT %s",
                (cutoff, limit),
            ).fetchall()
        for row in rows:
            self.observe_readiness(row["id"], row["instance_id"], wait=False)
        return len(rows)

    # ---------------------------------------------------------- housekeeping

    def housekeeping(self) -> None:
        now_dt = self.clock()
        now = to_db_time(now_dt)
        with self._tx() as conn:
            conn.execute(
                "UPDATE plans SET status = 'expired' WHERE status = 'ready' AND expires_at <= %s",
                (now,),
            )
            conn.execute(
                "UPDATE worker_heartbeats SET heartbeat_at = %s WHERE worker_id = %s",
                (now, self.worker_id),
            )
        if self._self_check_due():
            self.self_check()
        if self._healthy:
            self.refresh_readiness()
        cutoff = to_db_time(now_dt - timedelta(days=self.settings.workdir_retention_days))
        with self.db.read() as conn:
            # A failed or uncertain apply's work directory can hold the only recovery state
            # (Terraform writes errored.tfstate there if the backend write fails). Keep it
            # while any obligation for that apply is open, whatever happened since.
            rows = conn.execute(
                "SELECT plans.id, plans.deployment_id FROM plans WHERE plans.created_at < %s AND ("
                "plans.status IN ('superseded', 'expired', 'rejected', 'failed', 'applied') "
                "OR (plans.status = 'apply_failed' "
                "  AND EXISTS (SELECT 1 FROM recovery_obligations o WHERE o.plan_id = plans.id) "
                "  AND NOT EXISTS (SELECT 1 FROM recovery_obligations o "
                "    WHERE o.plan_id = plans.id AND o.discharged_at IS NULL)))",
                (cutoff,),
            ).fetchall()
        for row in rows:
            path = self.settings.workdir_root / row["deployment_id"] / row["id"]
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)


def main() -> None:
    secure_process_defaults()
    configure_logging()
    settings = load_settings()
    db = Database(settings.database_url, settings.database_schema)
    db.require_current_schema()
    # The inherited local flock remains the orphan-recovery proof. Pin this database to
    # that host and durable directory so a second host cannot recover live work merely
    # because it can reach PostgreSQL. Moving storage requires an explicit operator action.
    with db.transaction() as conn:
        conn.execute(
            (
                "INSERT INTO worker_storage_binding (hostname,workdir_root) "
                "VALUES (%s,%s) ON CONFLICT DO NOTHING"
            ),
            (socket.gethostname(), str(settings.workdir_root.resolve())),
        )
        binding = conn.execute(
            "SELECT hostname,workdir_root FROM worker_storage_binding"
        ).fetchone()
        if (
            binding is None
            or binding["hostname"] != socket.gethostname()
            or binding["workdir_root"] != str(settings.workdir_root.resolve())
        ):
            raise SystemExit("database is bound to another worker storage location")
    lock = WorkerLock(settings.worker_lock_path)
    fd = lock.acquire()
    provisioner = build_provisioner(settings, inherit_fds=(fd,))
    if provisioner is None:
        raise SystemExit("provisioner=disabled: the worker has nothing to do")
    worker = Worker(settings, db, provisioner)

    def _stop(signum: int, _frame: FrameType | None) -> None:
        log.info("stopping after the current job", extra={"fields": {"signal": signum}})
        worker.stop()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info(
        "worker started",
        extra={"fields": {"worker_id": worker.worker_id, "provisioner": provisioner.kind}},
    )
    try:
        worker.run_forever()
    finally:
        lock.release()
