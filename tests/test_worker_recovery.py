"""Crash, timeout, partial apply/delete and single-worker lock behaviour."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conftest import FAKE_AWS_KEY_ID, Harness, approve_current, auth, create_and_plan, launch
from unitcompute.provisioning.base import (
    ApplyResult,
    DeploymentSpec,
    ProvisioningError,
    ProvisioningTimeout,
)
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.worker import Worker, WorkerLock, WorkerLockHeld


def detail(h: Harness, dep: str) -> dict[str, Any]:
    body: dict[str, Any] = h.client.get(f"/deployments/{dep}", headers=auth()).json()
    return body


class FailingApply(SimulatedProvisioner):
    """Applies part of the plan (security group only), then fails like Terraform would."""

    def __init__(self, data_dir: Path, error: ProvisioningError, partial: bool) -> None:
        super().__init__(data_dir)
        self.error = error
        self.partial = partial

    def apply(self, spec: DeploymentSpec, workdir: Path, plan_path: Path) -> ApplyResult:
        intent = json.loads(plan_path.read_bytes())
        if self.partial and intent["kind"] == "create":
            sg = intent["desired"]["aws_security_group.vm"]
            path = self._state_path(spec.deployment_id)
            path.write_text(json.dumps({"aws_security_group.vm": sg}))
        raise self.error


def _worker(h: Harness, provisioner: SimulatedProvisioner) -> Worker:
    return Worker(h.settings, h.db, provisioner, clock=h.clock, worker_id="w2")


@pytest.mark.parametrize(
    "error",
    [
        ProvisioningError("terraform_apply_failed", "terraform apply failed; see the job log."),
        ProvisioningTimeout("terraform_timeout", "terraform apply exceeded its 1800s limit."),
    ],
)
def test_partial_apply_requires_recovery_then_reconciles(
    harness: Harness, error: ProvisioningError
) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    failing = FailingApply(h.settings.data_dir, error, partial=True)
    assert _worker(h, failing).run_once()
    after = detail(h, d["id"])
    assert after["status"] == "recovery_required"
    assert after["latest_job"]["status"] == "recovery_required"
    assert after["latest_job"]["error"]["code"] == error.code
    assert "partially" in after["status_reason"]
    # The security group really exists (billable/partial state) ...
    assert [r.resource_type for r in h.provisioner.owned_resources(d["id"])] == ["security_group"]

    # ... and a new preview reconciles from state: SG is a no-op, the VM is created.
    assert h.client.post(f"/deployments/{d['id']}/plan", headers=auth()).status_code == 202
    h.drain()
    repaired = detail(h, d["id"])
    if isinstance(error, ProvisioningTimeout):
        # Terraform was killed: stored state is not final and no errored.tfstate exists,
        # so what the apply created is unknown. Fail closed (round 5).
        assert repaired["status"] == "recovery_required"
        assert repaired["current_plan"]["error"]["code"] == "recovery_evidence_missing"
        return
    assert repaired["status"] == "awaiting_approval"
    assert [c["address"] for c in repaired["current_plan"]["resource_changes"]] == [
        "aws_instance.vm"
    ]
    approve_current(h, repaired)
    h.drain()
    assert detail(h, d["id"])["status"] == "active"


def test_recovery_can_choose_cleanup(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    _worker(
        h,
        FailingApply(
            h.settings.data_dir, ProvisioningError("terraform_apply_failed", "failed"), True
        ),
    ).run_once()
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    h.drain()
    pending = detail(h, d["id"])
    assert pending["status"] == "awaiting_deletion_approval"
    approve_current(h, pending)
    h.drain()
    assert detail(h, d["id"])["status"] == "deleted"
    assert h.provisioner.owned_resources(d["id"]) == []


def test_worker_crash_mid_apply_marks_recovery(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    crashed = h.worker()
    job = crashed.claim()  # claimed and "running" when the process dies
    assert job is not None and job["kind"] == "apply"

    successor = Worker(h.settings, h.db, h.provisioner, clock=h.clock, worker_id="w-new")
    assert successor.recover_interrupted() == [job["id"]]
    after = detail(h, d["id"])
    assert after["status"] == "recovery_required"
    assert after["latest_job"]["error"]["code"] == "worker_interrupted"
    # No blind replay: the interrupted job is not re-queued.
    assert successor.run_once() is False


def test_worker_crash_mid_plan_is_safe_to_fail(harness: Harness) -> None:
    h = harness
    created = h.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth()
    ).json()
    job = h.worker().claim()
    assert job is not None
    Worker(h.settings, h.db, h.provisioner, clock=h.clock).recover_interrupted()
    after = detail(h, created["deployment_id"])
    assert after["status"] == "plan_failed"
    assert after["latest_job"]["status"] == "failed"
    assert (
        h.client.post(f"/deployments/{created['deployment_id']}/plan", headers=auth()).status_code
        == 202
    )


class LeakyDestroy(SimulatedProvisioner):
    def apply(self, spec: DeploymentSpec, workdir: Path, plan_path: Path) -> ApplyResult:
        return ApplyResult()  # claims success but leaves resources behind


def test_deletion_only_completes_when_resources_verified_gone(harness: Harness) -> None:
    h = harness
    d = launch(h)
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    h.drain()
    approve_current(h, detail(h, d["id"]))
    _worker(h, LeakyDestroy(h.settings.data_dir)).run_once()
    after = detail(h, d["id"])
    assert after["status"] == "recovery_required"
    assert after["latest_job"]["error"]["code"] == "resources_remaining"
    # Quota stays reserved because the VM may still be billable.
    assert (
        h.client.post(
            "/deployments", json={"name": "next", "disk_gib": 8}, headers=auth()
        ).status_code
        == 409
    )


def test_create_verification_failure_requires_recovery(harness: Harness) -> None:
    class NoInstance(SimulatedProvisioner):
        def owned_resources(self, deployment_id: str) -> list[Any]:
            return []

    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    _worker(h, NoInstance(h.settings.data_dir)).run_once()
    after = detail(h, d["id"])
    assert after["status"] == "recovery_required"
    assert after["latest_job"]["error"]["code"] == "verification_failed"


def test_orphan_detected_on_replan(harness: Harness) -> None:
    class Orphans(SimulatedProvisioner):
        def owned_resources(self, deployment_id: str) -> list[Any]:
            from unitcompute.provisioning.base import OwnedResource

            return [OwnedResource("instance", "i-0untracked", "running")]

    h = harness
    created = h.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth()
    ).json()
    _worker(h, Orphans(h.settings.data_dir)).run_once()
    after = detail(h, created["deployment_id"])
    assert after["status"] == "plan_failed"
    assert after["current_plan"]["status"] == "rejected"
    assert "i-0untracked" in after["current_plan"]["error"]["message"]


def test_planning_errors_are_sanitized(harness: Harness) -> None:
    class Boom(SimulatedProvisioner):
        def plan(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError(f"{FAKE_AWS_KEY_ID} secret stack details")

    h = harness
    created = h.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth()
    ).json()
    _worker(h, Boom(h.settings.data_dir)).run_once()
    text = json.dumps(detail(h, created["deployment_id"]))
    assert "AKIA" not in text and "stack details" not in text
    assert "internal_error" in text


def test_housekeeping_expires_plans_and_prunes_old_workdirs(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    h.client.post(f"/deployments/{d['id']}/plan", headers=auth())
    h.drain()
    old = h.settings.workdir_root / d["id"] / d["current_plan"]["plan_id"]
    assert old.is_dir()
    h.clock.advance(days=8)
    h.worker().housekeeping()
    assert not old.exists()
    with h.db.read() as conn:
        statuses = {r["status"] for r in conn.execute("SELECT status FROM plans")}
    assert statuses == {"superseded", "expired"}


def test_workdirs_are_private(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    workdir = h.settings.workdir_root / d["id"] / d["current_plan"]["plan_id"]
    assert workdir.stat().st_mode & 0o077 == 0
    assert (workdir / "tfplan").stat().st_mode & 0o277 == 0
    assert h.settings.database_path.stat().st_mode & 0o077 == 0


def test_single_worker_lock(tmp_path: Path) -> None:
    first = WorkerLock(tmp_path / "worker.lock")
    fd = first.acquire()
    with pytest.raises(WorkerLockHeld):
        WorkerLock(tmp_path / "worker.lock").acquire()
    # A Terraform child inherits the lock and keeps it held after the worker lets go.
    child = subprocess.Popen(["sleep", "2"], pass_fds=(fd,))
    try:
        first.release()
        with pytest.raises(WorkerLockHeld):
            WorkerLock(tmp_path / "worker.lock").acquire()
    finally:
        child.wait()
    WorkerLock(tmp_path / "worker.lock").acquire()


def test_failed_repair_preview_keeps_recovery_status(harness: Harness) -> None:
    class Orphans(SimulatedProvisioner):
        def owned_resources(self, deployment_id: str) -> list[Any]:
            from unitcompute.provisioning.base import OwnedResource

            return [OwnedResource("instance", "i-0untracked", "running")]

    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    _worker(
        h,
        FailingApply(
            h.settings.data_dir, ProvisioningError("terraform_apply_failed", "failed"), True
        ),
    ).run_once()
    h.client.post(f"/deployments/{d['id']}/plan", headers=auth())
    _worker(h, Orphans(h.settings.data_dir)).run_once()
    after = detail(h, d["id"])
    assert after["current_plan"]["status"] == "rejected"
    assert after["status"] == "recovery_required"
