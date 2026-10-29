from __future__ import annotations

import pytest

from conftest import Harness, auth, create_and_plan, launch


def test_requests_without_token_are_rejected(harness: Harness) -> None:
    for method, path in [("get", "/deployments"), ("post", "/agent/messages")]:
        response = getattr(harness.client, method)(path)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.json()["error"]["code"] == "unauthenticated"


@pytest.mark.parametrize(
    "header", ["Basic abc", "Bearer", "Bearer dev:Alice", "Bearer x y", "Bearer dev:alice;drop"]
)
def test_malformed_tokens_rejected(harness: Harness, header: str) -> None:
    assert harness.client.get("/deployments", headers={"Authorization": header}).status_code == 401


def test_cross_user_access_is_non_enumerating(harness: Harness) -> None:
    h = harness
    detail = launch(h, "alice")
    dep, plan = detail["id"], detail["current_plan"]
    job_id = detail["latest_job"]["id"]
    missing_dep = "dep_" + "0" * 32
    missing_job = "job_" + "0" * 32

    def both(method: str, real: str, fake: str, **kw: object) -> None:
        a = getattr(h.client, method)(real, headers=auth("mallory"), **kw)
        b = getattr(h.client, method)(fake, headers=auth("mallory"), **kw)
        assert a.status_code == b.status_code == 404
        assert a.json()["error"]["code"] == b.json()["error"]["code"] == "not_found"
        assert a.json()["error"]["message"] == b.json()["error"]["message"]

    both("get", f"/deployments/{dep}", f"/deployments/{missing_dep}")
    both("post", f"/deployments/{dep}/plan", f"/deployments/{missing_dep}/plan")
    both("post", f"/deployments/{dep}/deletion-plan", f"/deployments/{missing_dep}/deletion-plan")
    both(
        "post",
        f"/deployments/{dep}/approve",
        f"/deployments/{missing_dep}/approve",
        json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
    )
    both("get", f"/jobs/{job_id}", f"/jobs/{missing_job}")

    assert h.client.get("/deployments", headers=auth("mallory")).json() == {"deployments": []}
    # Alice's deployment is untouched by the attempts.
    assert h.client.get(f"/deployments/{dep}", headers=auth()).json()["status"] == "active"


def test_cannot_approve_own_deployment_with_another_users_plan(harness: Harness) -> None:
    h = harness
    alice = create_and_plan(h, "alice")
    bob = create_and_plan(h, "bob")
    response = h.client.post(
        f"/deployments/{alice['id']}/approve",
        json={
            "plan_id": bob["current_plan"]["plan_id"],
            "plan_hash": bob["current_plan"]["plan_hash"],
        },
        headers=auth("alice"),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "plan_not_current"
    with h.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM jobs WHERE kind = 'apply'").fetchone()[0] == 0


@pytest.mark.parametrize(
    "path",
    [
        "/deployments/../../etc/passwd",
        "/deployments/dep_..%2f..%2fetc",
        "/deployments/dep_ABC",
        "/jobs/job_;rm -rf /",
    ],
)
def test_identifier_injection_rejected(harness: Harness, path: str) -> None:
    assert harness.client.get(path, headers=auth()).status_code in {404, 422}


def test_owner_cannot_be_supplied_by_client(harness: Harness) -> None:
    response = harness.client.post(
        "/deployments",
        json={"name": "demo", "disk_gib": 8, "owner_id": "dev:bob"},
        headers=auth("alice"),
    )
    assert response.status_code == 422
