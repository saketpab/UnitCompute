"""End-to-end offline lifecycle through the real API, service, worker and policy layers.

The provisioner is the clearly labelled simulator: these tests prove application behaviour,
not AWS behaviour.
"""

from __future__ import annotations

import json

from conftest import Harness, approve_current, auth, create_and_plan, launch


def test_full_lifecycle_create_inspect_delete(harness: Harness) -> None:
    h = harness
    created = h.client.post("/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth())
    assert created.status_code == 202
    body = created.json()
    assert body["status"] == "planning"
    assert body["deployment_id"].startswith("dep_")

    job = h.client.get(f"/jobs/{body['job_id']}", headers=auth()).json()
    assert job["status"] == "queued" and job["kind"] == "plan"

    assert h.drain() == 1
    detail = h.client.get(f"/deployments/{body['deployment_id']}", headers=auth()).json()
    plan = detail["current_plan"]
    assert detail["status"] == "awaiting_approval"
    assert plan["status"] == "ready" and plan["kind"] == "create"
    assert len(plan["plan_hash"]) == 64
    assert plan["cost"]["monthly_total_usd"] == "11.88"
    assert {c["address"] for c in plan["resource_changes"]} == {
        "aws_instance.vm",
        "aws_security_group.vm",
        "aws_ec2_instance_state.vm",
    }
    instance = next(c for c in plan["resource_changes"] if c["address"] == "aws_instance.vm")
    assert instance["summary"]["imdsv2_required"] is True
    assert instance["summary"]["root_disk_encrypted"] is True
    assert any("SIMULATED" in w for w in plan["warnings"])
    assert plan["provenance"]["provisioner"] == "simulated"

    approved = approve_current(h, detail)
    assert approved["status"] == "applying"
    assert h.drain() == 1
    active = h.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert active["status"] == "active"
    assert active["resources"]["instance_id"].startswith("i-")
    assert active["access"]["method"] == "ssm-session-manager"
    assert active["access"]["command"] is None  # simulated: nothing to connect to
    assert h.provisioner.owned_resources(detail["id"])

    deletion = h.client.post(f"/deployments/{detail['id']}/deletion-plan", headers=auth())
    assert deletion.status_code == 202
    h.drain()
    pending = h.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert pending["status"] == "awaiting_deletion_approval"
    dplan = pending["current_plan"]
    assert dplan["kind"] == "destroy"
    assert {c["action"] for c in dplan["resource_changes"]} == {"delete"}
    assert any("permanently deletes" in w for w in dplan["warnings"])

    approve_current(h, pending)
    h.drain()
    gone = h.client.get(f"/deployments/{detail['id']}", headers=auth()).json()
    assert gone["status"] == "deleted"
    assert gone["latest_job"]["status"] == "succeeded"
    assert h.provisioner.owned_resources(detail["id"]) == []

    # Quota is released once the VM is verified gone.
    again = h.client.post("/deployments", json={"name": "demo2", "disk_gib": 10}, headers=auth())
    assert again.status_code == 202

    with h.db.read() as conn:
        actions = [
            r["action"]
            for r in conn.execute(
                "SELECT action FROM audit_events WHERE deployment_id = ? ORDER BY id",
                (detail["id"],),
            )
        ]
    assert actions == [
        "deployment.requested",
        "plan.ready",
        "plan.approved",
        "apply.started",
        "deployment.active",
        "deletion_plan.requested",
        "plan.ready",
        "plan.approved",
        "apply.started",
        "deployment.deleted",
    ]


def test_cost_scales_with_disk(harness: Harness) -> None:
    detail = create_and_plan(harness, disk_gib=30)
    assert detail["current_plan"]["cost"]["monthly_total_usd"] == "13.64"


def test_refresh_plan_supersedes_previous(harness: Harness) -> None:
    h = harness
    detail = create_and_plan(h)
    old_plan = detail["current_plan"]
    response = h.client.post(f"/deployments/{detail['id']}/plan", headers=auth())
    assert response.status_code == 202
    h.drain()
    with h.db.read() as conn:
        status = conn.execute(
            "SELECT status FROM plans WHERE id = ?", (old_plan["plan_id"],)
        ).fetchone()["status"]
    assert status == "superseded"
    stale = h.client.post(
        f"/deployments/{detail['id']}/approve",
        json={"plan_id": old_plan["plan_id"], "plan_hash": old_plan["plan_hash"]},
        headers=auth(),
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "plan_not_current"


def test_cannot_plan_while_job_active(harness: Harness) -> None:
    h = harness
    created = h.client.post(
        "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth()
    ).json()
    response = h.client.post(f"/deployments/{created['deployment_id']}/plan", headers=auth())
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "invalid_state"


def test_quota_one_live_vm_per_user(harness: Harness) -> None:
    h = harness
    launch(h)
    second = h.client.post("/deployments", json={"name": "other", "disk_gib": 8}, headers=auth())
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "quota_exceeded"
    # Other users are unaffected.
    assert (
        h.client.post(
            "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth("bob")
        ).status_code
        == 202
    )


def test_provisioning_disabled_by_default(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from conftest import make_settings
    from unitcompute.api.app import create_app
    from unitcompute.db.database import Database

    settings = make_settings(tmp_path, provisioner="disabled")
    Database(settings.database_path).migrate()
    with TestClient(create_app(settings)) as client:
        response = client.post("/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "provisioning_disabled"


def test_job_result_is_safe(harness: Harness) -> None:
    h = harness
    detail = launch(h)
    job = h.client.get(f"/jobs/{detail['latest_job']['id']}", headers=auth()).json()
    text = json.dumps(job)
    assert job["status"] == "succeeded"
    assert "plan_path" not in text and "/data/" not in text
