"""HTTP platform concerns: limits, errors, CORS, OpenAPI, readiness, migrations, restart."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import FakeClock, Harness, auth, create_and_plan, launch, make_settings
from unitcompute.api.app import build_container, create_app
from unitcompute.db.database import LATEST_SCHEMA_VERSION, Database
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.services.deployments import DeploymentService
from unitcompute.worker import Worker


def test_body_size_limit_declared(harness: Harness) -> None:
    body = '{"name": "demo", "disk_gib": 8, "pad": "' + "x" * 20000 + '"}'
    response = harness.client.post(
        "/deployments", content=body, headers={**auth(), "Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_body_size_limit_streamed(harness: Harness) -> None:
    def chunks() -> Any:
        for _ in range(40):
            yield b"x" * 1024

    response = harness.client.post(
        "/deployments", content=chunks(), headers={**auth(), "Content-Type": "application/json"}
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    "body",
    [
        {"name": "demo", "disk_gib": 7},
        {"name": "demo", "disk_gib": 31},
        {"name": "demo", "disk_gib": "8"},
        {"name": "demo", "disk_gib": 8.0},
        {"name": "demo", "disk_gib": True},
        {"name": "Demo", "disk_gib": 8},
        {"name": "de", "disk_gib": 8},
        {"name": "demo; rm -rf /", "disk_gib": 8},
        {"name": "../etc", "disk_gib": 8},
        {"name": "demo", "disk_gib": 8, "region": "eu-west-1"},
        {"name": "demo", "disk_gib": 8, "ami_id": "ami-0123"},
        {"name": "demo", "disk_gib": 8, "user_data": "#!/bin/sh"},
        {"name": "demo", "disk_gib": 8, "hcl": "resource {}"},
        {"name": "demo"},
    ],
)
def test_invalid_deployment_requests(harness: Harness, body: dict[str, Any]) -> None:
    response = harness.client.post("/deployments", json=body, headers=auth())
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_input"
    assert error["request_id"] == response.headers["X-Request-ID"]
    assert "rm -rf" not in response.text  # inputs are not echoed back


def test_error_shape_and_headers(harness: Harness) -> None:
    response = harness.client.get("/deployments/dep_" + "a" * 32, headers=auth())
    assert response.status_code == 404
    assert set(response.json()["error"]) == {"code", "message", "request_id", "details"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_cors_is_restricted(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, cors_origins="https://app.example.test")
    Database(settings.database_path).migrate()
    with TestClient(create_app(settings)) as client:
        good = client.options(
            "/deployments",
            headers={
                "Origin": "https://app.example.test",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Idempotency-Key",
            },
        )
        bad = client.options(
            "/deployments",
            headers={
                "Origin": "https://evil.example.test",
                "Access-Control-Request-Method": "POST",
            },
        )
    assert good.headers["access-control-allow-origin"] == "https://app.example.test"
    assert "access-control-allow-credentials" not in good.headers
    assert "access-control-allow-origin" not in bad.headers


def test_openapi_documents_contract(harness: Harness) -> None:
    spec = harness.client.get("/openapi.json").json()
    paths = spec["paths"]
    assert set(paths) == {
        "/agent/messages",
        "/deployments",
        "/deployments/{deployment_id}",
        "/deployments/{deployment_id}/plan",
        "/deployments/{deployment_id}/deletion-plan",
        "/deployments/{deployment_id}/approve",
        "/jobs/{job_id}",
    }
    create = paths["/deployments"]["post"]
    assert "202" in create["responses"] and "409" in create["responses"]
    headers = [p["name"] for p in create["parameters"] if p["in"] == "header"]
    assert "Idempotency-Key" in headers
    assert "Idempotency-Key" in [
        p["name"] for p in paths["/deployments/{deployment_id}/approve"]["post"]["parameters"]
    ]


def test_readiness(harness: Harness) -> None:
    worker = Worker(harness.settings, harness.db, SimulatedProvisioner(harness.settings.data_dir))
    assert worker.self_check()
    response = harness.client.get("/readyz")
    ready = response.json()
    assert response.status_code == 200
    assert ready["ready"] is True
    assert ready["checks"]["schema_version"] == LATEST_SCHEMA_VERSION
    assert ready["checks"]["worker_self_check_ok"] is True
    assert harness.client.get("/healthz").json() == {"status": "ok"}


def test_api_refuses_unmigrated_database(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    with pytest.raises(RuntimeError, match="unitcompute-admin migrate"):
        create_app(settings)


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    db = Database(make_settings(tmp_path).database_path)
    assert db.migrate() == [1, 2, 3, 4, 5, 6, 7]
    assert db.migrate() == []
    assert db.schema_version() == LATEST_SCHEMA_VERSION


def test_state_survives_restart(harness: Harness) -> None:
    h = harness
    active = launch(h)
    pending = h.client.post(f"/deployments/{active['id']}/deletion-plan", headers=auth())
    assert pending.status_code == 202

    # New process: fresh Database/app/worker objects over the same files.
    settings = h.settings
    db = Database(settings.database_path)
    container = build_container(
        settings, deployments=DeploymentService(db, settings, clock=h.clock)
    )
    with TestClient(create_app(settings, container)) as client:
        restored = client.get(f"/deployments/{active['id']}", headers=auth()).json()
        assert restored["status"] == "deletion_planning"
        assert restored["resources"]["instance_id"] == active["resources"]["instance_id"]
        worker = Worker(settings, db, SimulatedProvisioner(settings.data_dir), clock=h.clock)
        assert worker.run_once()
        assert (
            client.get(f"/deployments/{active['id']}", headers=auth()).json()["status"]
            == "awaiting_deletion_approval"
        )


def test_list_only_returns_own(harness: Harness) -> None:
    create_and_plan(harness, "alice")
    create_and_plan(harness, "bob")
    names = [
        d["id"]
        for d in harness.client.get("/deployments", headers=auth("alice")).json()["deployments"]
    ]
    assert len(names) == 1


def test_worker_never_leaves_job_running_after_crash(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    detail = create_and_plan(h)
    h.client.post(
        f"/deployments/{detail['id']}/approve",
        json={
            "plan_id": detail["current_plan"]["plan_id"],
            "plan_hash": detail["current_plan"]["plan_hash"],
        },
        headers=auth(),
    )
    worker = h.worker()

    def broken(*args: Any, **kwargs: Any) -> None:
        raise KeyError("bug")

    monkeypatch.setattr(worker, "_finish_apply_success", broken)
    worker.run_once()
    after = h.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert after["latest_job"]["status"] == "recovery_required"
    assert after["status"] == "recovery_required"


def test_fresh_clock_isolation() -> None:
    assert FakeClock()().year == 2026
