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
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import FrameType
from typing import Any

from unitcompute.config import ProvisionerKind, Settings, load_settings
from unitcompute.db.database import Database, from_db_time, to_db_time, utcnow
from unitcompute.logging_setup import configure_logging, redact, secure_process_defaults
from unitcompute.pricing import estimate_monthly_cost
from unitcompute.provisioning.base import (
    DeploymentSpec,
    PlanKind,
    Provisioner,
    ProvisioningError,
    owner_tag,
    sha256_file,
)
from unitcompute.provisioning.factory import build_provisioner
from unitcompute.provisioning.policy import evaluate_plan
from unitcompute.services.deployments import (
    Clock,
    expected_versions,
    plan_expiry,
    plan_versions,
    record_audit,
)

log = logging.getLogger(__name__)
ACTOR = "system:worker"
HEARTBEAT_SECONDS = 15
_ID = re.compile(r"^(dep|plan)_[0-9a-f]{32}$")


class WorkerLockHeld(RuntimeError):
    pass


class WorkerLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def acquire(self) -> int:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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

    # ------------------------------------------------------------ lifecycle

    def stop(self) -> None:
        self._stop.set()

    def register(self) -> None:
        now = to_db_time(self.clock())
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO worker_heartbeats (worker_id, started_at, heartbeat_at) "
                "VALUES (?, ?, ?)",
                (self.worker_id, now, now),
            )

    def recover_interrupted(self) -> list[str]:
        """Call only while holding the worker lock: any 'running' job is orphaned."""
        now = to_db_time(self.clock())
        recovered: list[str] = []
        with self.db.transaction() as conn:
            rows = conn.execute(
                "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
                "ON plans.id = jobs.plan_id WHERE jobs.status = 'running'"
            ).fetchall()
            for job in rows:
                recovered.append(job["id"])
                if job["kind"] == "plan":
                    self._finish_plan_failure(
                        conn,
                        job,
                        "worker_interrupted",
                        "Planning was interrupted; request a new preview.",
                    )
                    continue
                reason = (
                    "The worker stopped while applying. AWS may hold partially created "
                    "or deleted resources; request a new preview to reconcile."
                )
                conn.execute(
                    "UPDATE jobs SET status = 'recovery_required', finished_at = ?, "
                    "error_code = 'worker_interrupted', error_message = ? WHERE id = ?",
                    (now, reason, job["id"]),
                )
                conn.execute(
                    "UPDATE plans SET status = 'apply_failed' WHERE id = ?", (job["plan_id"],)
                )
                conn.execute(
                    "UPDATE deployments SET status = 'recovery_required', status_reason = ?, "
                    "updated_at = ? WHERE id = ?",
                    (reason, now, job["deployment_id"]),
                )
                record_audit(
                    conn,
                    actor=ACTOR,
                    action="job.recovery_required",
                    deployment_id=job["deployment_id"],
                    plan_id=job["plan_id"],
                    job_id=job["id"],
                    detail={"reason": "worker_interrupted"},
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

    def claim(self) -> sqlite3.Row | None:
        now = to_db_time(self.clock())
        with self.db.transaction() as conn:
            job = conn.execute(
                "SELECT * FROM jobs WHERE status = 'queued' ORDER BY rowid LIMIT 1"
            ).fetchone()
            if job is None:
                return None
            conn.execute(
                "UPDATE jobs SET status = 'running', worker_id = ?, started_at = ?, "
                "heartbeat_at = ? WHERE id = ? AND status = 'queued'",
                (self.worker_id, now, now, job["id"]),
            )
            row: sqlite3.Row = conn.execute(
                "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
                "ON plans.id = jobs.plan_id WHERE jobs.id = ?",
                (job["id"],),
            ).fetchone()
            return row

    def run_once(self) -> bool:
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

    def _finish_crashed(self, job: sqlite3.Row) -> None:
        with self.db.read() as conn:
            current = conn.execute("SELECT status FROM jobs WHERE id = ?", (job["id"],)).fetchone()
        if current is None or current["status"] != "running":
            return
        if job["kind"] == "plan":
            with self.db.transaction() as conn:
                self._finish_plan_failure(
                    conn,
                    job,
                    "internal_error",
                    "Planning failed unexpectedly; request a new preview.",
                )
        else:
            self._recovery_required(job, "internal_error", "Apply processing failed unexpectedly.")

    def _heartbeat(self, job_id: str, stop: threading.Event) -> None:
        while not stop.wait(HEARTBEAT_SECONDS):
            try:
                now = to_db_time(self.clock())
                with self.db.transaction() as conn:
                    conn.execute("UPDATE jobs SET heartbeat_at = ? WHERE id = ?", (now, job_id))
                    conn.execute(
                        "UPDATE worker_heartbeats SET heartbeat_at = ? WHERE worker_id = ?",
                        (now, self.worker_id),
                    )
            except Exception:
                log.warning("heartbeat update failed", exc_info=True)

    def _load(self, job: sqlite3.Row) -> tuple[sqlite3.Row, sqlite3.Row]:
        with self.db.read() as conn:
            deployment = conn.execute(
                "SELECT * FROM deployments WHERE id = ?", (job["deployment_id"],)
            ).fetchone()
            plan = conn.execute("SELECT * FROM plans WHERE id = ?", (job["plan_id"],)).fetchone()
        return deployment, plan

    @staticmethod
    def _spec(deployment: sqlite3.Row) -> DeploymentSpec:
        return DeploymentSpec(
            deployment_id=deployment["id"],
            owner_tag=owner_tag(deployment["owner_id"]),
            name=deployment["name"],
            disk_gib=deployment["disk_gib"],
            region=deployment["region"],
            instance_type=deployment["instance_type"],
        )

    def workdir(self, deployment_id: str, plan_id: str) -> Path:
        if not (_ID.fullmatch(deployment_id) and _ID.fullmatch(plan_id)):
            raise JobFailure("invalid_identifier", "Invalid deployment or plan identifier.")
        self.settings.workdir_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root = self.settings.workdir_root.resolve()
        path = (root / deployment_id / plan_id).resolve()
        if not path.is_relative_to(root):
            raise JobFailure("invalid_identifier", "Invalid work directory.")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    def _finish_plan_failure(
        self,
        conn: sqlite3.Connection,
        job: sqlite3.Row,
        code: str,
        message: str,
        plan_status: str = "failed",
    ) -> None:
        now = to_db_time(self.clock())
        message = redact(message)[:2000]
        conn.execute(
            "UPDATE jobs SET status = 'failed', finished_at = ?, error_code = ?, "
            "error_message = ? WHERE id = ?",
            (now, code, message, job["id"]),
        )
        conn.execute(
            "UPDATE plans SET status = ?, error_code = ?, error_message = ? "
            "WHERE id = ? AND status IN ('pending', 'approved')",
            (plan_status, code, message, job["plan_id"]),
        )
        # A deployment whose last apply needs recovery stays recovery_required until a later
        # apply succeeds, so a failed repair preview cannot hide partial resources.
        unresolved = conn.execute(
            "SELECT status FROM jobs WHERE deployment_id = ? AND kind = 'apply' "
            "ORDER BY rowid DESC LIMIT 1",
            (job["deployment_id"],),
        ).fetchone()
        status = (
            "recovery_required"
            if unresolved is not None and unresolved["status"] == "recovery_required"
            else "plan_failed"
        )
        conn.execute(
            "UPDATE deployments SET status = ?, status_reason = ?, updated_at = ? "
            "WHERE id = ? AND current_plan_id = ?",
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

    def process_plan(self, job: sqlite3.Row) -> None:
        deployment, plan = self._load(job)
        kind: PlanKind = plan["kind"]
        try:
            if plan["status"] != "pending" or deployment["current_plan_id"] != plan["id"]:
                raise JobFailure("plan_superseded", "A newer plan replaced this one.")
            spec = self._spec(deployment)
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
            inventory = self.provisioner.owned_resources(spec.deployment_id)
            policy = evaluate_plan(
                result.plan_json,
                kind=kind,
                spec=spec,
                targets=self.provisioner.network_targets(),
                ami_id=result.ami_id,
                inventory=inventory,
            )
        except JobFailure as exc:
            with self.db.transaction() as conn:
                self._finish_plan_failure(conn, job, exc.code, exc.message)
            return
        except ProvisioningError as exc:
            log.warning("plan failed", extra={"fields": {"job_id": job["id"], "code": exc.code}})
            with self.db.transaction() as conn:
                self._finish_plan_failure(conn, job, exc.code, exc.safe_message)
            return
        except Exception:
            log.exception("unexpected planning failure", extra={"fields": {"job_id": job["id"]}})
            with self.db.transaction() as conn:
                self._finish_plan_failure(
                    conn,
                    job,
                    "internal_error",
                    "Planning failed unexpectedly; an operator was notified.",
                )
            return

        now_dt = self.clock()
        now = to_db_time(now_dt)
        with self.db.transaction() as conn:
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
                "UPDATE plans SET status = 'ready', plan_hash = ?, plan_path = ?, "
                "preview_json = ?, cost_json = ?, template_hash = ?, terraform_version = ?, "
                "provider_versions_json = ?, account_id = ?, ami_id = ?, ready_at = ?, "
                "expires_at = ? WHERE id = ? AND status = 'pending'",
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
                "UPDATE deployments SET status = ?, status_reason = NULL, updated_at = ? "
                "WHERE id = ? AND current_plan_id = ?",
                (status, now, deployment["id"], plan["id"]),
            )
            conn.execute(
                "UPDATE jobs SET status = 'succeeded', finished_at = ?, result_json = ? "
                "WHERE id = ?",
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

    def _precheck_apply(
        self, job: sqlite3.Row, deployment: sqlite3.Row, plan: sqlite3.Row, now: datetime
    ) -> Path:
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
        if from_db_time(plan["expires_at"]) <= now:
            raise JobFailure(
                "plan_expired",
                "The approved plan expired before it could run; "
                "request a fresh preview and approve it.",
            )
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
        workdir = self.workdir(deployment["id"], plan["id"])
        plan_path = Path(plan["plan_path"] or "")
        if plan_path.resolve() != (workdir / "tfplan").resolve() or not plan_path.is_file():
            raise JobFailure("plan_missing", "The saved plan file is missing.")
        if sha256_file(plan_path) != plan["plan_hash"]:
            raise JobFailure("plan_hash_mismatch", "The saved plan changed after approval.")
        return plan_path

    def process_apply(self, job: sqlite3.Row) -> None:
        deployment, plan = self._load(job)
        spec = self._spec(deployment)
        try:
            plan_path = self._precheck_apply(job, deployment, plan, self.clock())
        except (JobFailure, ProvisioningError) as exc:
            code = exc.code
            message = exc.message if isinstance(exc, JobFailure) else exc.safe_message
            with self.db.transaction() as conn:
                self._finish_plan_failure(conn, job, code, message)
            return

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE deployments SET apply_attempted = 1, "
                "ami_id = COALESCE(?, ami_id), updated_at = ? WHERE id = ?",
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

        try:
            outcome = self.provisioner.apply(spec, plan_path.parent, plan_path)
            inventory = self.provisioner.owned_resources(spec.deployment_id)
        except ProvisioningError as exc:
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
            if not instance_id or not any(r.resource_id == instance_id for r in inventory):
                self._recovery_required(
                    job, "verification_failed", "Apply finished but the VM could not be verified."
                )
                return
            try:
                ssm = self.provisioner.ssm_ping_status(instance_id)
            except Exception:  # best-effort status only; never fails a verified apply
                log.warning("ssm status lookup failed", exc_info=True)
                ssm = None
            result.update(instance_id=instance_id)
            with self.db.transaction() as conn:
                conn.execute(
                    "UPDATE deployments SET status = 'active', status_reason = NULL, "
                    "instance_id = ?, security_group_id = ?, ssm_ping_status = ?, "
                    "updated_at = ? WHERE id = ?",
                    (
                        instance_id,
                        outcome.outputs.get("security_group_id"),
                        ssm,
                        now,
                        deployment["id"],
                    ),
                )
                self._finish_apply_success(conn, job, plan, result, "deployment.active")
            return

        remaining = [f"{r.resource_type}:{r.resource_id}" for r in inventory]
        if remaining:
            self._recovery_required(
                job,
                "resources_remaining",
                "Delete ran but owned resources still exist: " + ", ".join(remaining),
            )
            return
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE deployments SET status = 'deleted', status_reason = NULL, "
                "ssm_ping_status = NULL, updated_at = ? WHERE id = ?",
                (now, deployment["id"]),
            )
            self._finish_apply_success(conn, job, plan, result, "deployment.deleted")

    def _finish_apply_success(
        self,
        conn: sqlite3.Connection,
        job: sqlite3.Row,
        plan: sqlite3.Row,
        result: dict[str, Any],
        action: str,
    ) -> None:
        now = to_db_time(self.clock())
        conn.execute("UPDATE plans SET status = 'applied' WHERE id = ?", (plan["id"],))
        conn.execute(
            "UPDATE jobs SET status = 'succeeded', finished_at = ?, result_json = ? WHERE id = ?",
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

    def _recovery_required(self, job: sqlite3.Row, code: str, message: str) -> None:
        message = redact(message)[:2000]
        now = to_db_time(self.clock())
        reason = (
            f"{message} AWS may hold partially changed resources; request a new preview "
            "to reconcile. Resources that cannot be reconciled need an operator."
        )
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'recovery_required', finished_at = ?, error_code = ?, "
                "error_message = ? WHERE id = ?",
                (now, code, message, job["id"]),
            )
            conn.execute(
                "UPDATE plans SET status = 'apply_failed', error_code = ?, "
                "error_message = ? WHERE id = ?",
                (code, message, job["plan_id"]),
            )
            conn.execute(
                "UPDATE deployments SET status = 'recovery_required', status_reason = ?, "
                "updated_at = ? WHERE id = ?",
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

    # ---------------------------------------------------------- housekeeping

    def housekeeping(self) -> None:
        now_dt = self.clock()
        now = to_db_time(now_dt)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE plans SET status = 'expired' WHERE status = 'ready' AND expires_at <= ?",
                (now,),
            )
            conn.execute(
                "UPDATE worker_heartbeats SET heartbeat_at = ? WHERE worker_id = ?",
                (now, self.worker_id),
            )
        cutoff = to_db_time(now_dt - timedelta(days=self.settings.workdir_retention_days))
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT plans.id, plans.deployment_id FROM plans JOIN deployments "
                "ON deployments.id = plans.deployment_id WHERE plans.created_at < ? AND ("
                "plans.status IN ('superseded', 'expired', 'rejected', 'failed', 'applied') "
                "OR (plans.status = 'apply_failed' AND deployments.status <> 'recovery_required'))",
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
    db = Database(settings.database_path)
    db.require_current_schema()
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
