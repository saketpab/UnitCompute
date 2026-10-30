from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from conftest import Harness, auth, create_and_plan
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.errors import Conflict, ServiceUnavailable
from unitcompute.schemas import ApprovalRequest, DeploymentRequest

ALICE = Principal(subject="dev:alice", auth_method="dev")


def test_same_key_same_payload_returns_original(harness: Harness) -> None:
    headers = {**auth(), "Idempotency-Key": "create-demo-0001"}
    first = harness.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers=headers
    )
    second = harness.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers=headers
    )
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    with harness.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM deployments").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1


def test_same_key_different_payload_conflicts(harness: Harness) -> None:
    headers = {**auth(), "Idempotency-Key": "create-demo-0002"}
    harness.client.post("/deployments", json={"name": "demo", "disk_gib": 8}, headers=headers)
    other = harness.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 9}, headers=headers
    )
    assert other.status_code == 409
    assert other.json()["error"]["code"] == "idempotency_key_reused"


def test_keys_are_scoped_per_user(harness: Harness) -> None:
    key = {"Idempotency-Key": "shared-key-0003"}
    a = harness.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers={**auth("alice"), **key}
    )
    b = harness.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers={**auth("bob"), **key}
    )
    assert a.status_code == b.status_code == 202
    assert a.json()["deployment_id"] != b.json()["deployment_id"]


def test_approve_idempotent_replay(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    headers = {**auth(), "Idempotency-Key": "approve-0004-abc"}
    body = {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]}
    first = harness.client.post(f"/deployments/{detail['id']}/approve", json=body, headers=headers)
    second = harness.client.post(f"/deployments/{detail['id']}/approve", json=body, headers=headers)
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()


@pytest.mark.parametrize("key", ["short", "has space here", "x" * 129, "semi;colon-key"])
def test_invalid_idempotency_key(harness: Harness, key: str) -> None:
    response = harness.client.post(
        "/deployments",
        json={"name": "demo", "disk_gib": 8},
        headers={**auth(), "Idempotency-Key": key},
    )
    assert response.status_code == 422


def test_concurrent_creates_reserve_quota_once(harness: Harness) -> None:
    service = harness.container.deployments
    barrier = threading.Barrier(8)

    def attempt(i: int) -> str:
        barrier.wait()
        try:
            service.create_deployment(
                ALICE, DeploymentRequest(name=f"vm-{i}x", disk_gib=8), None, None
            )
        except Conflict as exc:
            return exc.code
        except ServiceUnavailable as exc:
            return exc.code
        return "created"

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("created") == 1
    assert set(results) <= {"created", "quota_exceeded", "database_busy"}
    with harness.db.read() as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM deployments WHERE owner_id = 'dev:alice'"
            ).fetchone()[0]
            == 1
        )


def test_concurrent_approvals_queue_one_apply(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    service = harness.container.deployments
    barrier = threading.Barrier(6)

    def attempt(_: int) -> str:
        barrier.wait()
        try:
            service.approve(
                ALICE,
                detail["id"],
                ApprovalRequest(plan_id=plan["plan_id"], plan_hash=plan["plan_hash"]),
                None,
                None,
            )
        except (Conflict, ServiceUnavailable) as exc:
            return exc.code
        return "approved"

    with ThreadPoolExecutor(6) as pool:
        results = list(pool.map(attempt, range(6)))
    assert results.count("approved") == 1
    with harness.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM jobs WHERE kind = 'apply'").fetchone()[0] == 1


def test_unique_index_backstops_quota(harness: Harness) -> None:
    """Even if the service check were bypassed, the database refuses a second live VM."""
    create_and_plan(harness)
    with pytest.raises(psycopg.IntegrityError), harness.db.transaction() as conn:
        conn.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, regio"
            "n, instance_type, provisioner, status, created_at, updated_a"
            "t) VALUES ('dep_x', 'dev:alice', 'b', 8, 'us-east-1', 't3.mi"
            "cro', 'simulated', 'planning', '2026-10-30T00:00:00Z', '2026"
            "-10-30T00:00:00Z')"
        )


def test_unique_active_job_per_deployment(harness: Harness) -> None:
    detail = create_and_plan(harness)
    rows = [(job, detail["id"], detail["current_plan"]["plan_id"]) for job in ("job_a", "job_b")]
    with pytest.raises(psycopg.IntegrityError), harness.db.transaction() as conn:
        conn.cursor().executemany(
            "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
            "payload_hash, created_at) VALUES (%s, 'dev:alice', %s, %s, 'apply', 'queued', "
            "'h', '2026-10-30T00:00:00Z')",
            rows,
        )


def test_lock_contention_returns_retryable_503(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 50)
    blocker = harness.db.connect()
    blocker.execute("BEGIN")
    blocker.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (harness.settings.database_schema + ":writes",),
    )
    try:
        response = harness.client.post(
            "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth()
        )
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "database_busy"
    assert (
        harness.client.post(
            "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth()
        ).status_code
        == 202
    )
