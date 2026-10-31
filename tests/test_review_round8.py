"""Regressions for the eighth independent review round of 256356c.

Adapted from the reviewers' ``test_independent_r8.py`` and ``test_round8_independent.py``.
IDs match docs/verification-ledger.md.
"""

from __future__ import annotations

import stat
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import FakeClock, Harness, approve_current, auth, create_and_plan, launch
from test_review_round2 import _client, _detail
from test_review_round5 import _obligations
from test_review_round7 import (
    _CountingApply,
    _failed_create_then_empty_delete,
    _schema4,
    _status,
)
from unitcompute.db.database import Database
from unitcompute.provisioning import base
from unitcompute.provisioning.aws import TemporaryCredentials
from unitcompute.provisioning.base import ApplyResult, DeploymentSpec, NotStarted
from unitcompute.provisioning.runner import RunResult, TerraformRunner
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.provisioning.terraform import TerraformProvisioner
from unitcompute.worker import Worker

OLD = "dep_" + "a" * 32


def _old_unproven_deployment(db: Database, owner: str = "dev:alice") -> None:
    """The owner's earlier deployment: recorded as deleted, its create apply never captured."""
    with db.transaction() as c:
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, apply_attempted, created_at, updated_at) VALUES "
            "(%s, %s, 'old', 8, 'us-east-1', 't3.micro', 'simulated', 'deleted', 1, "
            "'2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00')",
            (OLD, owner),
        )
        c.execute(
            "INSERT INTO recovery_obligations (deployment_id, reason, evidence, created_at) "
            "VALUES (%s, 'evidence_revalidation', 'uncaptured', '2026-10-01T00:00:00+00:00')",
            (OLD,),
        )


def _post(h: Harness, dep: str, route: str, user: str = "alice") -> Any:
    return h.client.post(f"/deployments/{dep}/{route}", headers=auth(user))


# ============ R8-1: an unresolved create anywhere for the owner stops create and repair work


def test_r8_1_queued_reservation_cannot_plan_while_an_older_create_is_unproven(
    harness: Harness,
) -> None:
    """The reviewer's lifecycle: a reservation made before the obligation existed is
    already queued. It must not plan, approve or launch."""
    h = harness
    response = h.client.post("/deployments", json={"name": "newer", "disk_gib": 8}, headers=auth())
    assert response.status_code == 202
    newer = response.json()["deployment_id"]
    _old_unproven_deployment(h.db)  # the upgrade finds the older unproven create
    h.drain()
    detail = _detail(h, newer)
    assert detail["current_plan"]["status"] == "failed"
    assert detail["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert h.provisioner.owned_resources(newer) == []
    assert _status(h.db, newer) != "active"


def test_r8_1_a_ready_plan_cannot_be_approved_but_cleanup_can(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    _old_unproven_deployment(h.db)
    plan = d["current_plan"]
    refused = h.client.post(
        f"/deployments/{d['id']}/approve",
        json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
        headers=auth(),
    )
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "recovery_required"
    assert refused.json()["error"]["details"] == {"deployment_id": OLD}
    # Cleanup of what exists is still possible.
    assert _post(h, d["id"], "deletion-plan").status_code == 202
    h.drain()
    pending = _detail(h, d["id"])
    assert pending["status"] == "awaiting_deletion_approval"
    approve_current(h, pending)
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"
    assert _obligations(h, OLD) == [("evidence_revalidation", "uncaptured", False)]


def test_r8_1_an_approved_and_queued_apply_is_refused_by_the_worker(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)  # approved while nothing was unproven
    _old_unproven_deployment(h.db)  # ... then the obligation appears before the worker runs
    _CountingApply.calls = []
    Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock).run_once()
    assert _CountingApply.calls == []
    detail = _detail(h, d["id"])
    assert detail["latest_job"]["error"]["code"] == "recovery_evidence_missing"
    assert detail["status"] != "active" and h.provisioner.owned_resources(d["id"]) == []
    assert _post(h, d["id"], "deletion-plan").status_code == 202  # still deletable
    h.drain()
    approve_current(h, _detail(h, d["id"]))
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"


def test_r8_1_repair_of_a_running_vm_is_blocked_but_its_deletion_is_not(harness: Harness) -> None:
    h = harness
    d = launch(h)
    _old_unproven_deployment(h.db)
    assert _post(h, d["id"], "plan").status_code == 202  # a repair preview
    h.drain()
    repair = _detail(h, d["id"])
    assert repair["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert _post(h, d["id"], "deletion-plan").status_code == 202
    h.drain()
    pending = _detail(h, d["id"])
    assert pending["status"] == "awaiting_deletion_approval"
    approve_current(h, pending)
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"
    # the owner cannot create again until the older create is resolved
    again = h.client.post("/deployments", json={"name": "next", "disk_gib": 8}, headers=auth())
    assert (again.status_code, again.json()["error"]["code"]) == (409, "recovery_required")


def test_r8_1_other_owners_are_unaffected(harness: Harness) -> None:
    h = harness
    _old_unproven_deployment(h.db, "dev:alice")
    d = launch(h, "bob")
    assert _detail_for(h, d["id"], "bob")["status"] == "active"


def _detail_for(h: Harness, dep: str, user: str) -> dict[str, Any]:
    body: dict[str, Any] = h.client.get(f"/deployments/{dep}", headers=auth(user)).json()
    return body


def test_r8_1_schema4_upgrade_with_a_preexisting_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's scenario end to end: a schema-4 database with an older failed create
    followed by an empty deletion, and a newer reservation already queued. After the
    upgrade the reservation cannot plan; deleting it is still possible."""
    settings, db = _schema4(tmp_path, monkeypatch)
    _failed_create_then_empty_delete(db, OLD, "dev:alice", "deleted", "2026-10-01", "1")
    newer, plan_id, job_id = "dep_" + "b" * 32, "plan_" + "c" * 32, "job_" + "d" * 32
    with db.transaction() as c:  # what the old service wrote for POST /deployments
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, current_plan_id, created_at, updated_at) VALUES "
            "(%s, 'dev:alice', 'newer', 8, 'us-east-1', 't3.micro', 'simulated', 'planning', "
            "NULL, '2026-10-02T00:00:00+00:00', '2026-10-02T00:00:00+00:00')",
            (newer,),
        )
        c.execute(
            "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
            "config_hash, region, state_key, template_version, created_at) VALUES "
            "(%s, %s, 'dev:alice', 'create', 'pending', 'simulated', 'h', 'us-east-1', 'k', "
            "'ec2-vm/v1', '2026-10-02T00:00:00+00:00')",
            (plan_id, newer),
        )
        c.execute("UPDATE deployments SET current_plan_id = %s WHERE id = %s", (plan_id, newer))
        c.execute(
            "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
            "payload_hash, created_at) VALUES (%s, 'dev:alice', %s, %s, 'plan', 'queued', 'h', "
            "'2026-10-02T00:00:00+00:00')",
            (job_id, newer, plan_id),
        )
    assert db.migrate() == [5, 6, 7, 8, 9, 10, 11]
    client, h = _client(settings, db, FakeClock())
    provisioner = SimulatedProvisioner(settings.data_dir)
    with client:
        worker = Worker(settings, db, provisioner, clock=h.clock)
        while worker.run_once():
            pass
        body = client.get(f"/deployments/{newer}", headers=auth()).json()
        assert body["current_plan"]["error"]["code"] == "recovery_evidence_missing"
        assert provisioner.owned_resources(newer) == []
        assert client.post(f"/deployments/{newer}/deletion-plan", headers=auth()).status_code == 202
        while worker.run_once():
            pass
        pending = client.get(f"/deployments/{newer}", headers=auth()).json()
        assert pending["status"] == "awaiting_deletion_approval"
        plan = pending["current_plan"]
        approved = client.post(
            f"/deployments/{newer}/approve",
            json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
            headers=auth(),
        )
        assert approved.status_code == 202
        while worker.run_once():
            pass
        assert client.get(f"/deployments/{newer}", headers=auth()).json()["status"] == "deleted"


# ============== R8-2: expiry is judged at the dispatch boundary, after every preparation step


class _TimedAws:
    """Credential exchange that takes ``delay`` (injected clock) and records ordering."""

    def __init__(self, clock: FakeClock, delay: float, events: list[str]) -> None:
        self.clock, self.delay, self.events = clock, delay, events

    def credentials(self, *args: Any) -> TemporaryCredentials:
        self.events.append("credentials")
        self.clock.advance(seconds=self.delay)
        return TemporaryCredentials("synthetic-key", "synthetic-secret", "synthetic-token")


class _RecordingRunner:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def base_env(self, workdir: Path) -> dict[str, str]:
        return {}

    def run(self, args: Any, **kwargs: Any) -> RunResult:
        self.events.append("run:" + args[0])
        return RunResult(0, "{}", "")


def _terraform(h: Harness, delay: float, events: list[str]) -> TerraformProvisioner:
    return TerraformProvisioner(
        h.settings,
        _RecordingRunner(events),
        _TimedAws(h.clock, delay, events),  # type: ignore[arg-type]
    )


def _deadline(h: Harness, seconds_left: float) -> Any:
    expiry = h.clock() + timedelta(seconds=seconds_left)

    def check() -> None:
        if h.clock() >= expiry:
            raise NotStarted("plan_expired", "expired")

    return check


def _spec(dep: str = "dep_" + "e" * 32) -> DeploymentSpec:
    return DeploymentSpec(dep, "owner", "demo", 8, "us-east-1", "t3.micro")


def test_r8_2_the_provisioner_checks_after_the_credential_exchange(
    harness: Harness, tmp_path: Path
) -> None:
    """The boundary on its own: an exchange that crosses the deadline stops the spawn."""
    h = harness
    events: list[str] = []
    provisioner = _terraform(h, delay=119, events=events)
    work = tmp_path / "w"
    work.mkdir()
    with base.dispatch_guard(_deadline(h, 1)), pytest.raises(NotStarted) as exc:
        provisioner.apply(_spec(), work, work / "tfplan")
    assert exc.value.code == "plan_expired"
    assert events == ["credentials"]  # no run:apply


def test_r8_2_the_check_comes_after_preparation_and_before_the_spawn(
    harness: Harness, tmp_path: Path
) -> None:
    h = harness
    events: list[str] = []
    provisioner = _terraform(h, delay=0, events=events)
    work = tmp_path / "w"
    work.mkdir()

    def check() -> None:
        events.append("check")

    with base.dispatch_guard(check):
        provisioner.apply(_spec(), work, work / "tfplan")
    assert events == ["credentials", "check", "run:apply", "run:output"]


def test_r8_2_a_plan_with_time_left_still_applies(harness: Harness, tmp_path: Path) -> None:
    h = harness
    events: list[str] = []
    work = tmp_path / "w"
    work.mkdir()
    with base.dispatch_guard(_deadline(h, 30)):
        _terraform(h, delay=10, events=events).apply(_spec(), work, work / "tfplan")
    assert events == ["credentials", "run:apply", "run:output"]


def test_r8_2_the_guard_does_not_leak_outside_its_scope(harness: Harness) -> None:
    def refuse() -> None:
        raise NotStarted("plan_expired", "expired")

    with base.dispatch_guard(refuse), pytest.raises(NotStarted):
        base.check_dispatch()
    base.check_dispatch()  # no guard installed any more


def test_r8_2_the_simulator_honours_the_guard(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    refused: list[Any] = []

    def refuse() -> None:
        raise NotStarted("plan_expired", "expired")

    workdir = h.settings.workdir_root / d["id"] / d["current_plan"]["plan_id"]
    with base.dispatch_guard(refuse):
        try:
            h.provisioner.apply(_spec(d["id"]), workdir, workdir / "tfplan")
        except NotStarted as exc:
            refused.append(exc.code)
    assert refused == ["plan_expired"]
    assert h.provisioner.owned_resources(d["id"]) == []


def test_r8_2_worker_to_provisioner_to_runner_never_dispatches_an_expired_plan(
    harness: Harness,
) -> None:
    """Reviewer reproduction through the real worker and TerraformProvisioner.apply: the
    credential exchange alone crosses the expiry; the runner is never asked to apply, the
    job is a plain failure (nothing ran, so no recovery obligation), and the plan is dead."""
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=59)
    events: list[str] = []
    real = _terraform(h, delay=2, events=events)

    class UsesActualApply(SimulatedProvisioner):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            return real.apply(spec, workdir, plan_path)

    Worker(h.settings, h.db, UsesActualApply(h.settings.data_dir), clock=h.clock).run_once()
    assert events == ["credentials"]
    detail = _detail(h, d["id"])
    assert detail["latest_job"]["status"] == "failed"
    assert detail["latest_job"]["error"]["code"] == "plan_expired"
    assert detail["status"] == "plan_failed"
    assert _obligations(h, d["id"]) == []
    assert h.provisioner.owned_resources(d["id"]) == []
    base.check_dispatch()  # the guard was removed again


def test_r8_2_a_real_binary_is_never_spawned_for_an_expired_plan(
    harness: Harness, tmp_path: Path
) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=59)
    marker = tmp_path / "dispatched"
    binary = tmp_path / "synthetic-terraform"
    binary.write_text(
        f"#!{sys.executable}\nimport pathlib, sys\n"
        f"pathlib.Path({str(marker)!r}).write_text(' '.join(sys.argv[1:]))\n"
        "print('{}')\n"
    )
    binary.chmod(stat.S_IRWXU)
    real = TerraformProvisioner(
        h.settings,
        TerraformRunner(binary),
        _TimedAws(h.clock, 120, []),  # type: ignore[arg-type]
    )

    class UsesActualApply(SimulatedProvisioner):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            return real.apply(spec, workdir, plan_path)

    Worker(h.settings, h.db, UsesActualApply(h.settings.data_dir), clock=h.clock).run_once()
    assert not marker.exists()
    assert _detail(h, d["id"])["latest_job"]["error"]["code"] == "plan_expired"


def test_r8_2_worker_keeps_its_own_final_check_for_provisioners_that_ignore_the_guard(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Preserved from round 7: a provisioner that never calls the dispatch check is still
    stopped by the worker's check after the transaction."""
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=59)
    _CountingApply.calls = []
    worker = Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock)
    import unitcompute.worker as worker_module

    record_audit = worker_module.record_audit

    def slow_audit(conn: Any, **kwargs: Any) -> Any:
        result = record_audit(conn, **kwargs)
        if kwargs.get("action") == "apply.started":
            h.clock.advance(seconds=2)
        return result

    monkeypatch.setattr(worker_module, "record_audit", slow_audit)
    assert worker.run_once()
    assert _CountingApply.calls == []
