from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from unitcompute.api.app import Container, build_container, create_app
from unitcompute.config import Settings
from unitcompute.db.database import Database
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.services.deployments import DeploymentService
from unitcompute.worker import Worker


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(
            ("UNITCOMPUTE_", "AWS_", "ANTHROPIC_", "OPENAI_", "LANGSMITH_", "LANGCHAIN_")
        ):
            monkeypatch.delenv(key)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


# Shaped like an AWS access key ID so redaction is exercised; assembled at runtime so secret
# scanners do not flag a test literal.
FAKE_AWS_KEY_ID = "AKIA" + "TESTONLYNOTAKEY0"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "development",
        "data_dir": tmp_path / "data",
        "auth_mode": "dev",
        "provisioner": "simulated",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def db(settings: Settings) -> Database:
    database = Database(settings.database_path)
    database.migrate()
    return database


@dataclass
class Harness:
    settings: Settings
    db: Database
    client: TestClient
    container: Container
    provisioner: SimulatedProvisioner
    clock: FakeClock
    make_worker: Callable[[], Worker]

    def worker(self) -> Worker:
        return self.make_worker()

    def drain(self) -> int:
        worker = self.worker()
        count = 0
        while worker.run_once():
            count += 1
        return count


def auth(user: str = "alice") -> dict[str, str]:
    return {"Authorization": f"Bearer dev:{user}"}


@pytest.fixture
def harness(settings: Settings, db: Database, clock: FakeClock) -> Iterator[Harness]:
    provisioner = SimulatedProvisioner(settings.data_dir)
    deployments = DeploymentService(db, settings, clock=clock)
    container = build_container(settings, deployments=deployments)
    app = create_app(settings, container)

    def make_worker() -> Worker:
        return Worker(settings, db, provisioner, clock=clock, worker_id="test-worker")

    with TestClient(app) as client:
        yield Harness(settings, db, client, container, provisioner, clock, make_worker)


def create_and_plan(
    h: Harness, user: str = "alice", name: str = "demo", disk_gib: int = 8
) -> dict[str, Any]:
    response = h.client.post(
        "/deployments", json={"name": name, "disk_gib": disk_gib}, headers=auth(user)
    )
    assert response.status_code == 202, response.text
    h.drain()
    detail = h.client.get(
        f"/deployments/{response.json()['deployment_id']}", headers=auth(user)
    ).json()
    assert detail["status"] == "awaiting_approval", detail
    return detail


def approve_current(h: Harness, detail: dict[str, Any], user: str = "alice") -> dict[str, Any]:
    plan = detail["current_plan"]
    response = h.client.post(
        f"/deployments/{detail['id']}/approve",
        json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
        headers=auth(user),
    )
    assert response.status_code == 202, response.text
    body: dict[str, Any] = response.json()
    return body


def launch(h: Harness, user: str = "alice") -> dict[str, Any]:
    detail = create_and_plan(h, user)
    approve_current(h, detail, user)
    h.drain()
    final: dict[str, Any] = h.client.get(f"/deployments/{detail['id']}", headers=auth(user)).json()
    assert final["status"] == "active", final
    return final


@pytest.fixture
def moto_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """moto-emulated EC2 client (offline; proves request handling, not AWS behaviour)."""
    import boto3
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        yield boto3.client("ec2", region_name="us-east-1")
