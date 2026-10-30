"""Regressions for the seventh independent review round of 5756293.

Adapted from the reviewers' ``test_independent_reliability.py``, ``test_independent.py``,
``runner-memory-repro.py`` and the mutant evidence. IDs match docs/verification-ledger.md.
"""

from __future__ import annotations

import contextlib
import fcntl
import importlib.util
import json
import os
import stat
import sys
import threading
import time
import tracemalloc
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from conftest import (
    FakeClock,
    Harness,
    approve_current,
    auth,
    create_and_plan,
    make_settings,
)
from test_review_round2 import _client
from test_review_round5 import _obligations
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.errors import Conflict
from unitcompute.provisioning.base import ApplyResult, ProvisioningError, ProvisioningTimeout
from unitcompute.provisioning.runner import MAX_LOG_BYTES, MAX_STDOUT_BYTES, TerraformRunner
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.schemas import DeploymentRequest
from unitcompute.services.deployments import DeploymentService
from unitcompute.worker import Worker

ROOT = Path(__file__).resolve().parents[1]
ALICE = Principal(subject="dev:alice", auth_method="dev")


# ================= R7-1: an unproven deletion is surfaced and blocks new reservations


def _schema4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Database]:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    migrations = database._migration_files()
    with monkeypatch.context() as m:
        m.setattr(database, "_migration_files", lambda: migrations[:4])
        assert db.migrate() == [1, 2, 3, 4]
    return settings, db


_CREATE = '{"changes":[{"address":"aws_instance.vm","action":"create"}]}'


def _failed_create_then_empty_delete(
    db: Database, dep: str, owner: str, status: str, day: str, suffix: str
) -> None:
    """The reviewer's schema-4 history: a failed create, then an empty successful deletion."""
    with db.transaction() as c:
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, apply_attempted, created_at, updated_at) VALUES "
            "(%s, %s, 'demo', 8, 'us-east-1', 't3.micro', 'simulated', %s, 1, %s, %s)",
            (dep, owner, status, day, day),
        )
        if status != "deleted":
            return
        for n, (kind, plan_status, preview, job_status) in enumerate(
            [
                ("create", "apply_failed", _CREATE, "recovery_required"),
                ("destroy", "applied", '{"changes":[]}', "succeeded"),
            ]
        ):
            plan = f"plan_{suffix}{n}" + "0" * (31 - len(suffix))
            c.execute(
                (
                    "INSERT INTO plans (id, deployment_id, owner_id, kind, status"
                    ", provisioner, config_hash, region, state_key, template_vers"
                    "ion, preview_json, created_at) VALUES (%s, %s, %s, %s, %s, '"
                    "simulated', 'h', 'us-east-1', 'k', 'ec2-vm/v1', %s, %s)"
                ),
                (plan, dep, owner, kind, plan_status, preview, day),
            )
            c.execute(
                "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
                "payload_hash, created_at) VALUES (%s, %s, %s, %s, 'apply', %s, 'h', %s)",
                (f"job_{suffix}{n}" + "0" * (31 - len(suffix)), owner, dep, plan, job_status, day),
            )


def _status(db: Database, dep: str) -> str:
    with db.read() as c:
        return str(c.execute("SELECT status FROM deployments WHERE id = %s", (dep,)).fetchone()[0])


def _open_uncaptured(db: Database) -> list[str]:
    with db.read() as c:
        return [
            r[0]
            for r in c.execute(
                "SELECT deployment_id FROM recovery_obligations "
                "WHERE discharged_at IS NULL AND evidence = 'uncaptured' ORDER BY id"
            )
        ]


def test_r7_1_deleted_deployment_with_unproven_obligation_becomes_recovery_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reliability reproduction: after upgrade the deployment is no longer 'deleted' and the
    owner cannot reserve another VM."""
    settings, db = _schema4(tmp_path, monkeypatch)
    dep = "dep_" + "a" * 32
    _failed_create_then_empty_delete(db, dep, "dev:alice", "deleted", "2026-10-01", "1")
    assert db.migrate() == [5, 6, 7, 8]
    assert _status(db, dep) == "recovery_required"
    assert _open_uncaptured(db) == [dep]
    service = DeploymentService(db, settings)
    with pytest.raises(Conflict) as exc:
        service.create_deployment(ALICE, DeploymentRequest(name="second", disk_gib=8), None, None)
    assert exc.value.code == "quota_exceeded"  # the recovery deployment holds the slot
    client, _ = _client(settings, db, FakeClock())
    with client:
        response = client.post(
            "/deployments", json={"name": "second", "disk_gib": 8}, headers=auth()
        )
        assert response.status_code == 409


def test_r7_1_owner_with_a_newer_deployment_keeps_both_rows_and_the_obligation_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """The one-live-VM unique index forbids a second non-deleted row, so the old row stays
    'deleted'; migration must not fail, the obligation stays open and listed, and reserving
    again stays blocked even after the newer VM is deleted."""
    settings, db = _schema4(tmp_path, monkeypatch)
    old, new = "dep_" + "a" * 32, "dep_" + "b" * 32
    _failed_create_then_empty_delete(db, old, "dev:alice", "deleted", "2026-10-01", "1")
    _failed_create_then_empty_delete(db, new, "dev:alice", "active", "2026-10-02", "2")
    assert db.migrate() == [5, 6, 7, 8]  # no unique-index violation
    assert _status(db, old) == "deleted" and _status(db, new) == "active"
    assert _open_uncaptured(db) == [old]
    from unitcompute import admin

    monkeypatch.setattr(admin, "load_settings", lambda: settings)
    capsys.readouterr()
    assert admin.main(["recovery-report"]) == 0
    reported = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [r["id"] for r in reported] == [old]
    assert reported[0]["open_recovery_obligations"][0]["evidence"] == "uncaptured"
    with db.transaction() as c:  # the newer VM is later deleted
        c.execute("UPDATE deployments SET status = 'deleted' WHERE id = %s", (new,))
    service = DeploymentService(db, settings)
    with pytest.raises(Conflict) as exc:
        service.create_deployment(ALICE, DeploymentRequest(name="third", disk_gib=8), None, None)
    assert exc.value.code == "recovery_required"
    assert exc.value.details == {"deployment_id": old}


def test_r7_1_only_one_row_per_owner_is_reopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, db = _schema4(tmp_path, monkeypatch)
    first, second = "dep_" + "a" * 32, "dep_" + "b" * 32
    _failed_create_then_empty_delete(db, first, "dev:alice", "deleted", "2026-10-01", "1")
    _failed_create_then_empty_delete(db, second, "dev:alice", "deleted", "2026-10-02", "2")
    assert db.migrate() == [5, 6, 7, 8]
    assert {_status(db, first), _status(db, second)} == {"deleted", "recovery_required"}
    assert _status(db, second) == "recovery_required"  # the newest holds the slot
    assert sorted(_open_uncaptured(db)) == [first, second]


def test_r7_1_owners_without_unproven_obligations_are_unaffected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, db = _schema4(tmp_path, monkeypatch)
    _failed_create_then_empty_delete(
        db, "dep_" + "a" * 32, "dev:alice", "deleted", "2026-10-01", "1"
    )
    with db.transaction() as c:  # bob: a clean deleted deployment, no history at all
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, created_at, updated_at) VALUES (%s, 'dev:bob', 'demo', 8, "
            "'us-east-1', 't3.micro', 'simulated', 'deleted', '2026-10-01', '2026-10-01')",
            ("dep_" + "c" * 32,),
        )
    db.migrate()
    assert _status(db, "dep_" + "c" * 32) == "deleted"
    service = DeploymentService(db, settings)
    status, _ = service.create_deployment(
        Principal(subject="dev:bob", auth_method="dev"),
        DeploymentRequest(name="second", disk_gib=8),
        None,
        None,
    )
    assert status == 202


def test_r7_1_runtime_guard_does_not_depend_on_the_migration(harness: Harness) -> None:
    """A deleted deployment that gains an open uncaptured obligation any other way still
    blocks reservations, and a captured or discharged one does not."""
    h = harness
    d = create_and_plan(h)
    with h.db.transaction() as c:
        c.execute("UPDATE deployments SET status = 'deleted' WHERE id = %s", (d["id"],))
        c.execute(
            "INSERT INTO recovery_obligations (deployment_id, reason, evidence, created_at) "
            "VALUES (%s, 'x', 'captured', '2026-10-30T00:00:00Z')",
            (d["id"],),
        )
    assert (
        h.client.post(
            "/deployments", json={"name": "next", "disk_gib": 8}, headers=auth()
        ).status_code
        == 202
    )


def test_r7_1_runtime_open_uncaptured_obligation_blocks_reservation(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    with h.db.transaction() as c:
        c.execute("UPDATE deployments SET status = 'deleted' WHERE id = %s", (d["id"],))
        c.execute(
            "INSERT INTO recovery_obligations (deployment_id, reason, evidence, created_at) "
            "VALUES (%s, 'x', 'uncaptured', '2026-10-30T00:00:00Z')",
            (d["id"],),
        )
    response = h.client.post("/deployments", json={"name": "next", "disk_gib": 8}, headers=auth())
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "recovery_required"
    assert response.json()["error"]["details"] == {"deployment_id": d["id"]}
    other = h.client.post("/deployments", json={"name": "next", "disk_gib": 8}, headers=auth("bob"))
    assert other.status_code == 202  # other owners are unaffected
    assert _obligations(h, d["id"]) == [("x", "uncaptured", False)]


# ====================== R7-2: expiry is judged after every wait, immediately before acting


class _CountingApply(SimulatedProvisioner):
    calls: ClassVar[list[Any]] = []

    def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
        type(self).calls.append(1)
        return super().apply(spec, workdir, plan_path)


def _no_apply_and_expired(h: Harness, dep: str) -> None:
    assert _CountingApply.calls == []
    detail = h.client.get(f"/deployments/{dep}", headers=auth()).json()
    assert detail["latest_job"]["error"]["code"] == "plan_expired"
    assert h.provisioner.owned_resources(dep) == []


def test_r7_2_worker_rejects_a_plan_that_expired_during_the_evidence_import(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=59)
    _CountingApply.calls = []
    worker = Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock)
    original = worker.import_identities

    def import_after_wait(dep: str) -> Any:
        h.clock.advance(seconds=2)
        return original(dep)

    monkeypatch.setattr(worker, "import_identities", import_after_wait)
    assert worker.run_once()
    _no_apply_and_expired(h, d["id"])


def test_r7_2_worker_with_a_real_evidence_lock_wait(harness: Harness) -> None:
    """Start 0.5 s before expiry on a monotonic clock; a real flock holds the evidence file
    for 1.5 s: the apply must not run."""
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    expiry = h.clock() + timedelta(minutes=15)
    start = time.monotonic()

    def clock() -> Any:
        return expiry - timedelta(seconds=0.5) + timedelta(seconds=time.monotonic() - start)

    path = h.settings.workdir_root / d["id"] / "identities.jsonl"
    path.write_bytes(b"")
    fd = os.open(path, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    timer = threading.Timer(1.5, os.close, args=(fd,))
    timer.start()
    _CountingApply.calls = []
    try:
        Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=clock).run_once()
    finally:
        timer.join()
    _no_apply_and_expired(h, d["id"])


def test_r7_2_worker_rejects_a_plan_that_expired_while_waiting_for_the_write_lock(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The apply.started transaction can wait for the database after the precheck returned;
    expiry is judged inside it, before anything records that an apply started."""
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=59)
    _CountingApply.calls = []
    worker = Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock)
    precheck = worker._precheck_apply

    def precheck_then_wait(*args: Any) -> Any:
        result = precheck(*args)
        h.clock.advance(seconds=2)  # the write lock is slow to arrive
        return result

    monkeypatch.setattr(worker, "_precheck_apply", precheck_then_wait)
    assert worker.run_once()
    _no_apply_and_expired(h, d["id"])
    with h.db.read() as c:
        started = c.execute(
            "SELECT apply_attempted FROM deployments WHERE id = %s", (d["id"],)
        ).fetchone()[0]
        audited = c.execute(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'apply.started'"
        ).fetchone()[0]
    assert (started, audited) == (0, 0)


def test_r7_2_worker_rechecks_immediately_before_dispatch(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Time passes after the in-transaction check (for example during its commit): only the
    final check, immediately before dispatch, stops the apply."""
    import unitcompute.worker as worker_module

    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=59)
    _CountingApply.calls = []
    worker = Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock)
    record_audit = worker_module.record_audit

    def slow_audit(conn: Any, **kwargs: Any) -> Any:
        result = record_audit(conn, **kwargs)
        if kwargs.get("action") == "apply.started":
            h.clock.advance(seconds=2)
        return result

    monkeypatch.setattr(worker_module, "record_audit", slow_audit)
    assert worker.run_once()
    _no_apply_and_expired(h, d["id"])


def test_r7_2_plan_still_applies_just_inside_the_window(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    h.clock.advance(minutes=14, seconds=58)
    _CountingApply.calls = []
    Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock).run_once()
    assert _CountingApply.calls == [1]
    assert h.client.get(f"/deployments/{d['id']}", headers=auth()).json()["status"] == "active"


def test_r7_2_approval_time_is_sampled_after_the_transaction_wait(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    d = create_and_plan(h)
    h.clock.advance(minutes=14, seconds=59)
    original = h.db.transaction

    @contextlib.contextmanager
    def waited(owner_id: str | None = None) -> Iterator[Any]:
        h.clock.advance(seconds=2)  # the PostgreSQL advisory lock can wait up to 5 s
        with original(owner_id) as conn:
            yield conn

    monkeypatch.setattr(h.db, "transaction", waited)
    plan = d["current_plan"]
    response = h.client.post(
        f"/deployments/{d['id']}/approve",
        json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
        headers=auth(),
    )
    assert response.status_code == 409
    assert h.client.get(f"/deployments/{d['id']}", headers=auth()).json()["status"] != "applying"


def test_r7_2_approval_with_a_real_postgresql_lock_wait(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    expiry = h.clock() + timedelta(minutes=15)
    locked = threading.Event()

    def hold() -> None:
        with h.db.transaction():
            locked.set()
            time.sleep(1.5)

    thread = threading.Thread(target=hold)
    thread.start()
    assert locked.wait(5)
    start = time.monotonic()

    def clock() -> Any:
        return expiry - timedelta(seconds=0.5) + timedelta(seconds=time.monotonic() - start)

    h.container.deployments = DeploymentService(h.db, h.settings, clock=clock)
    plan = d["current_plan"]
    try:
        response = h.client.post(
            f"/deployments/{d['id']}/approve",
            json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
            headers=auth(),
        )
    finally:
        thread.join()
    assert response.status_code == 409


# ============================== R7-3: subprocess output is drained into bounded buffers


def _child(tmp_path: Path, body: str) -> TerraformRunner:
    script = tmp_path / "synthetic-terraform"
    script.write_text(f"#!{sys.executable}\nimport os, sys, time, signal\n{body}\n")
    script.chmod(stat.S_IRWXU)
    return TerraformRunner(script)


def _run(runner: TerraformRunner, tmp_path: Path, timeout: float = 30) -> Any:
    return runner.run(
        ["version"],
        workdir=tmp_path,
        env=runner.base_env(tmp_path),
        timeout=timeout,
        log_name="synthetic",
    )


def test_r7_3_noisy_stderr_is_bounded(tmp_path: Path) -> None:
    runner = _child(tmp_path, "for _ in range(64): os.write(2, b'x' * (1 << 20))")
    tracemalloc.start()
    try:
        result = _run(runner, tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.returncode == 0
    assert peak < 4 * 1024 * 1024, peak  # was ~200 MB for 64 MiB
    assert len(result.stderr) == MAX_LOG_BYTES  # the tail, as before
    log = (tmp_path / "logs" / "synthetic.log").read_bytes()
    assert len(log) <= 2 * MAX_LOG_BYTES + 32


def test_r7_3_oversized_stdout_is_bounded_and_still_rejected(tmp_path: Path) -> None:
    runner = _child(tmp_path, "for _ in range(40): os.write(1, b'y' * (1 << 20))")
    tracemalloc.start()
    try:
        with pytest.raises(ProvisioningError) as exc:
            _run(runner, tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert exc.value.code == "terraform_output_too_large"
    assert peak < MAX_STDOUT_BYTES + 4 * 1024 * 1024, peak  # not 40 MiB x copies


def test_r7_3_stdout_within_the_limit_is_returned_intact(tmp_path: Path) -> None:
    runner = _child(
        tmp_path, "sys.stdout.write('{\"a\": \"' + 'z' * 300000 + '\"}'); sys.stderr.write('warn')"
    )
    result = _run(runner, tmp_path)
    assert json.loads(result.stdout) == {"a": "z" * 300000}
    assert result.stderr == "warn"


def test_r7_3_both_streams_full_at_once_do_not_deadlock(tmp_path: Path) -> None:
    runner = _child(
        tmp_path,
        "for _ in range(32):\n os.write(1, b'o' * 65536)\n os.write(2, b'e' * 65536)",
    )
    result = _run(runner, tmp_path, timeout=20)
    assert result.returncode == 0 and len(result.stdout) == 32 * 65536


def test_r7_3_timeout_still_kills_the_group_and_reports_a_timeout(tmp_path: Path) -> None:
    runner = _child(
        tmp_path,
        "import subprocess\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "os.write(2, b'noise' * 100000)\n"
        "time.sleep(60)",
    )
    started = time.monotonic()
    with pytest.raises(ProvisioningTimeout) as exc:
        runner.run(
            ["version"],
            workdir=tmp_path,
            env=runner.base_env(tmp_path),
            timeout=1,
            log_name="synthetic",
        )
    assert exc.value.code == "terraform_timeout"
    assert time.monotonic() - started < 60
    assert "terminated after timeout" in (tmp_path / "logs" / "synthetic.log").read_text()


def test_r7_3_a_lingering_grandchild_holding_the_pipes_is_a_timeout(tmp_path: Path) -> None:
    """The child exits at once but a descendant keeps stdout open: the run cannot be treated
    as finished (communicate() blocked the same way)."""
    runner = _child(
        tmp_path,
        "import subprocess\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])",
    )
    started = time.monotonic()
    with pytest.raises(ProvisioningTimeout):
        _run(runner, tmp_path, timeout=1.5)
    assert time.monotonic() - started < 40


def test_r7_3_signal_exit_is_reported_as_a_negative_return_code(tmp_path: Path) -> None:
    runner = _child(tmp_path, "os.kill(os.getpid(), signal.SIGKILL)")
    assert _run(runner, tmp_path).returncode == -9


# ======================== R7-4: the mutation runner must prove the *intended* failure


def _guards() -> Any:
    spec = importlib.util.spec_from_file_location(
        "check_guards", ROOT / "scripts" / "check_guards.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_guards"] = module
    spec.loader.exec_module(module)
    return module


_OLD = (
    "                        \"UPDATE agent_attempts SET status = 'failed', idempotency_key = NULL, \"\n"  # noqa: E501
    "                        \"finished_at = %s WHERE id = %s AND status = 'reserved'\",\n"
    "                        (to_db_time(utcnow()), attempt_id),\n"
)
_TEST = ("tests/test_review_round1.py::test_r3_failed_attempts_stay_counted",)


def test_r7_4_an_invalid_sql_mutant_is_not_counted_as_killed(tmp_path: Path) -> None:
    """Reviewer evidence: the old mutant produced invalid SQL, the test failed only because
    the statement raised, and the runner called that a kill."""
    guards = _guards()
    broken = guards.Mutation(
        "broken-sql",
        (
            (
                "agent/service.py",
                _OLD,
                _OLD.replace("UPDATE agent_attempts SET", "DELETE FROM agent_attempts SET"),
            ),
        ),
        _TEST,
    )
    outcome = guards.run(broken, tmp_path)
    assert outcome.startswith("BROKEN-MUTANT") and "SyntaxError" in outcome


def test_r7_4_the_valid_deletion_mutant_is_killed_by_the_rate_limit_assertion(
    tmp_path: Path,
) -> None:
    guards = _guards()
    mutant = next(m for m in guards.MUTATIONS if m.name == "r3-failed-attempts-counted")
    assert mutant.expect == "rate_limited"
    assert guards.run(mutant, tmp_path) == "KILLED"
    wrong = guards.Mutation(mutant.name, mutant.edits, mutant.tests, expect="no such text anywhere")
    assert guards.run(wrong, tmp_path) == "WRONG-REASON"


def test_r7_4_every_mutation_edit_is_syntactically_valid_python_or_sql() -> None:
    """Static audit of the whole inventory: apply each edit and compile the result."""
    guards = _guards()
    src = ROOT / "src" / "unitcompute"
    failures = []
    for mutation in guards.MUTATIONS:
        for relative, old, new in mutation.edits:
            text = (src / relative).read_text()
            assert text.count(old) == 1, (mutation.name, relative)
            mutated = text.replace(old, new)
            if relative.endswith(".py"):
                try:
                    compile(mutated, relative, "exec")
                except SyntaxError as exc:
                    failures.append((mutation.name, str(exc)))
    assert failures == []


def test_mutant_classifier_uses_actual_exception_diagnostics() -> None:
    guards = _guards()
    traceback = "    raise TypeError(\nE   AssertionError: expected 404, got 200\n"
    assert guards.broken_errors(traceback) == set()
    assert guards.broken_errors("E   psycopg.errors.IndeterminateDatatype: unknown parameter") == {
        "IndeterminateDatatype"
    }
    assert guards.broken_errors("E   psycopg.errors.DatatypeMismatch: boolean required") == {
        "DatatypeMismatch"
    }
    assert guards.broken_errors("TypeError: invalid call") == {"TypeError"}
