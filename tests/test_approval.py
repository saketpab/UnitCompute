"""Exact-plan approval: replay, tampering, expiry, staleness and worker rechecks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import Harness, approve_current, auth, create_and_plan


def _approve(h: Harness, dep: str, plan_id: str, plan_hash: str, user: str = "alice"):  # type: ignore[no-untyped-def]
    return h.client.post(
        f"/deployments/{dep}/approve",
        json={"plan_id": plan_id, "plan_hash": plan_hash},
        headers=auth(user),
    )


def _apply_jobs(h: Harness) -> int:
    with h.db.read() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM jobs WHERE kind = 'apply'").fetchone()[0])


def test_tampered_hash_rejected(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    wrong = ("0" if plan["plan_hash"][0] != "0" else "1") + plan["plan_hash"][1:]
    response = _approve(harness, detail["id"], plan["plan_id"], wrong)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "plan_hash_mismatch"
    assert _apply_jobs(harness) == 0


@pytest.mark.parametrize(
    "body",
    [
        {"plan_id": "plan_x", "plan_hash": "a" * 64},
        {"plan_id": "plan_" + "a" * 32, "plan_hash": "A" * 64},
        {"plan_id": "plan_" + "a" * 32},
        {"plan_id": "plan_" + "a" * 32, "plan_hash": "a" * 64, "auto_approve": True},
    ],
)
def test_malformed_approval_rejected(harness: Harness, body: dict[str, object]) -> None:
    detail = create_and_plan(harness)
    response = harness.client.post(
        f"/deployments/{detail['id']}/approve", json=body, headers=auth()
    )
    assert response.status_code == 422


def test_approval_replay_does_not_create_second_job(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    assert _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"]).status_code == 202
    replay = _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"])
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "plan_not_approvable"
    harness.drain()
    after = _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"])
    assert after.status_code == 409
    assert _apply_jobs(harness) == 1


def test_expired_plan_cannot_be_approved(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    harness.clock.advance(minutes=15, seconds=1)
    shown = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert shown["current_plan"]["status"] == "expired"
    response = _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "plan_expired"
    assert _apply_jobs(harness) == 0
    # A fresh preview can be requested and approved.
    assert (
        harness.client.post(f"/deployments/{detail['id']}/plan", headers=auth()).status_code == 202
    )
    harness.drain()
    fresh = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    approve_current(harness, fresh)


def test_plan_ttl_is_fifteen_minutes(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    harness.clock.advance(minutes=14, seconds=59)
    assert _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"]).status_code == 202


def test_stale_template_version_rejected(harness: Harness) -> None:
    detail = create_and_plan(harness)
    plan = detail["current_plan"]
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE plans SET template_hash = %s WHERE id = %s", ("f" * 64, plan["plan_id"])
        )
    response = _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "plan_stale"


def test_destroy_plan_cannot_be_approved_as_create(harness: Harness) -> None:
    """Approval binds plan type: an approval call cannot launch from a deletion preview."""
    from conftest import launch

    detail = launch(harness)
    harness.client.post(f"/deployments/{detail['id']}/deletion-plan", headers=auth())
    harness.drain()
    pending = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE deployments SET status = 'awaiting_approval' WHERE id = %s", (detail["id"],)
        )
    plan = pending["current_plan"]
    response = _approve(harness, detail["id"], plan["plan_id"], plan["plan_hash"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "invalid_state"


def _plan_file(h: Harness, plan_id: str) -> Path:
    with h.db.read() as conn:
        return Path(
            conn.execute("SELECT plan_path FROM plans WHERE id = %s", (plan_id,)).fetchone()[
                "plan_path"
            ]
        )


def test_worker_rejects_plan_file_modified_after_approval(harness: Harness) -> None:
    detail = create_and_plan(harness)
    approve_current(harness, detail)
    path = _plan_file(harness, detail["current_plan"]["plan_id"])
    os.chmod(path, 0o600)
    path.write_bytes(path.read_bytes().replace(b'"volume_size": 8', b'"volume_size": 30'))
    harness.drain()
    after = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert after["status"] == "plan_failed"
    assert after["latest_job"]["error"]["code"] == "plan_hash_mismatch"
    assert harness.provisioner.owned_resources(detail["id"]) == []


def test_worker_rejects_plan_that_expired_in_queue(harness: Harness) -> None:
    detail = create_and_plan(harness)
    harness.clock.advance(minutes=14)
    approve_current(harness, detail)
    harness.clock.advance(minutes=2)
    harness.drain()
    after = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert (after["latest_job"]["error"] or {}).get("code") == "plan_expired"
    assert harness.provisioner.owned_resources(detail["id"]) == []


def test_worker_rejects_approval_by_someone_else(harness: Harness) -> None:
    detail = create_and_plan(harness)
    approve_current(harness, detail)
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE plans SET approved_by = 'dev:mallory' WHERE id = %s",
            (detail["current_plan"]["plan_id"],),
        )
    harness.drain()
    after = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert (after["latest_job"]["error"] or {}).get("code") == "plan_not_approved"
    assert harness.provisioner.owned_resources(detail["id"]) == []


def test_worker_rejects_plan_file_outside_workdir(harness: Harness, tmp_path: Path) -> None:
    detail = create_and_plan(harness)
    approve_current(harness, detail)
    original = _plan_file(harness, detail["current_plan"]["plan_id"])
    elsewhere = tmp_path / "tfplan"
    elsewhere.write_bytes(original.read_bytes())
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE plans SET plan_path = %s WHERE id = %s",
            (str(elsewhere), detail["current_plan"]["plan_id"]),
        )
    harness.drain()
    after = harness.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert after["latest_job"]["error"]["code"] == "plan_missing"


def test_chat_yes_is_not_approval(harness: Harness) -> None:
    """Approval is only the explicit approve route; nothing else creates an apply job."""
    detail = create_and_plan(harness)
    harness.client.get(f"/deployments/{detail['id']}", headers=auth())
    harness.client.post(f"/deployments/{detail['id']}/plan", headers=auth())
    assert _apply_jobs(harness) == 0
