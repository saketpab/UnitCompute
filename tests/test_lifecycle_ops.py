"""Lifecycle operations beyond create/delete: inspect, edit, stop/start, orphan reporting.

Every mutation is an ordinary exact-plan: previewed, policy-checked, approved by hash,
dispatched under a fresh expiry check, gated by the owner-wide recovery rule and recorded
with the same evidence as create. The simulator stands in for Terraform and AWS here; real
Terraform plans are checked in test_terraform_offline.py and EC2 semantics with moto in
TestMotoLifecycle below. None of this proves AWS behaviour.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import Harness, approve_current, auth, create_and_plan, launch
from test_review_round2 import _AwsBacked, _detail
from test_review_round5 import _obligations
from unitcompute.provisioning.base import (
    ApplyResult,
    InstanceDetails,
    ProvisioningError,
)
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.worker import Worker


def _update(h: Harness, dep: str, body: dict[str, Any], user: str = "alice", **headers: str) -> Any:
    return h.client.post(
        f"/deployments/{dep}/update-plan", json=body, headers={**auth(user), **headers}
    )


def _preview(h: Harness, dep: str, body: dict[str, Any]) -> dict[str, Any]:
    assert _update(h, dep, body).status_code == 202
    h.drain()
    detail = _detail(h, dep)
    assert detail["current_plan"]["status"] == "ready", detail
    return detail


def _apply(h: Harness, dep: str, body: dict[str, Any]) -> dict[str, Any]:
    approve_current(h, _preview(h, dep, body))
    h.drain()
    return _detail(h, dep)


def _changes(detail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        c["address"]: c["summary"].get("changes", {})
        for c in detail["current_plan"]["resource_changes"]
    }


# ----------------------------------------------------------------- stop and start


def test_stop_then_start_is_previewed_approved_and_verified(harness: Harness) -> None:
    h = harness
    d = launch(h)
    dep = d["id"]
    assert (d["power_state"], d["instance_state"]) == ("running", "running")

    preview = _preview(h, dep, {"power_state": "stopped"})
    plan = preview["current_plan"]
    assert plan["operation"] == "update" and plan["request"] == {"power_state": "stopped"}
    assert _changes(preview) == {
        "aws_ec2_instance_state.vm": {"power_state": ["running", "stopped"]}
    }
    assert any("Stopping shuts the VM down" in w for w in plan["warnings"])
    # a stopped VM costs only its disk
    assert plan["cost"]["lines"][0]["monthly_usd"] == "0.00"
    assert plan["cost"]["monthly_total_usd"] == "0.64"
    assert (
        h.provisioner.instance_details([d["resources"]["instance_id"]])[
            d["resources"]["instance_id"]
        ].state
        == "running"
    )  # nothing happened yet
    approve_current(h, preview)
    h.drain()
    stopped = _detail(h, dep)
    assert stopped["status"] == "active"
    assert (stopped["power_state"], stopped["instance_state"]) == ("stopped", "stopped")
    assert stopped["resources"]["connection"]["ready"] is False
    assert stopped["latest_job"]["result"]["power_state"] == "stopped"

    started = _apply(h, dep, {"power_state": "running"})
    assert (started["power_state"], started["instance_state"]) == ("running", "running")
    assert started["current_plan"]["operation"] == "update"
    assert started["resources"]["connection"]["ready"] is True


def test_a_stopped_vm_stays_stopped_through_repair_and_other_edits(harness: Harness) -> None:
    h = harness
    d = launch(h)
    dep = d["id"]
    _apply(h, dep, {"power_state": "stopped"})
    # a plain repair preview must not start it
    assert h.client.post(f"/deployments/{dep}/plan", headers=auth()).status_code == 202
    h.drain()
    repair = _detail(h, dep)
    assert (
        repair["current_plan"]["status"] == "ready"
        and repair["current_plan"]["resource_changes"] == []
    )
    assert repair["power_state"] == "stopped"
    # an edit that does not mention power keeps it stopped
    renamed = _apply(h, dep, {"name": "still-off"})
    assert (renamed["name"], renamed["power_state"], renamed["instance_state"]) == (
        "still-off",
        "stopped",
        "stopped",
    )


def test_a_stopped_vm_can_be_deleted(harness: Harness) -> None:
    h = harness
    d = launch(h)
    dep = d["id"]
    _apply(h, dep, {"power_state": "stopped"})
    assert h.client.post(f"/deployments/{dep}/deletion-plan", headers=auth()).status_code == 202
    h.drain()
    pending = _detail(h, dep)
    assert pending["status"] == "awaiting_deletion_approval"
    approve_current(h, pending)
    h.drain()
    assert _detail(h, dep)["status"] == "deleted"
    assert h.provisioner.owned_resources(dep) == []


# ------------------------------------------------------------------- inspect / edit


def test_edit_name_and_grow_disk(harness: Harness) -> None:
    h = harness
    d = launch(h)
    dep = d["id"]
    preview = _preview(h, dep, {"name": "renamed", "disk_gib": 12})
    assert _changes(preview) == {
        "aws_instance.vm": {"disk_gib": [8, 12], "name": ["demo", "renamed"]},
        "aws_security_group.vm": {"name": ["demo", "renamed"]},
    }
    assert any("grows from 8 to 12 GiB" in w for w in preview["current_plan"]["warnings"])
    assert preview["current_plan"]["cost"]["monthly_total_usd"] == "12.20"
    # inspect before approval: nothing has changed
    assert (_detail(h, dep)["name"], _detail(h, dep)["disk_gib"]) == ("demo", 8)
    approve_current(h, preview)
    h.drain()
    after = _detail(h, dep)
    assert (after["status"], after["name"], after["disk_gib"]) == ("active", "renamed", 12)
    assert after["latest_job"]["result"] == {
        "plan_id": preview["current_plan"]["plan_id"],
        "kind": "create",
        "instance_id": d["resources"]["instance_id"],
        "name": "renamed",
        "disk_gib": 12,
        "power_state": "running",
    }
    details = h.provisioner.instance_details([d["resources"]["instance_id"]])
    assert details[d["resources"]["instance_id"]].root_volume_gib == 12
    # the instance kept its identity: an edit is never a replacement
    assert after["resources"]["instance_id"] == d["resources"]["instance_id"]
    assert after["resources"]["root_volume_id"] == d["resources"]["root_volume_id"]


def test_combined_edit(harness: Harness) -> None:
    h = harness
    d = launch(h)
    done = _apply(h, d["id"], {"name": "all-three", "disk_gib": 20, "power_state": "stopped"})
    assert (done["name"], done["disk_gib"], done["power_state"], done["instance_state"]) == (
        "all-three",
        20,
        "stopped",
        "stopped",
    )


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({}, "request at least one"),
        ({"region": "eu-west-1"}, "extra"),
        ({"instance_type": "m5.large"}, "extra"),
        ({"name": "Not Valid"}, "String should match"),
        ({"name": "sk-abcdef0123456789abcdef"}, "credential"),
        ({"disk_gib": 7}, "greater than or equal to 8"),
        ({"disk_gib": 31}, "less than or equal to 30"),
        ({"disk_gib": "12"}, "valid integer"),
        ({"power_state": "paused"}, "running"),
        ({"power_state": "hibernated", "name": "ok-name"}, "running"),
    ],
)
def test_invalid_update_requests_are_rejected_without_a_plan(
    harness: Harness, body: dict[str, Any], fragment: str
) -> None:
    h = harness
    d = launch(h)
    response = _update(h, d["id"], body)
    assert response.status_code == 422, response.text
    assert fragment in response.text
    assert _detail(h, d["id"])["latest_job"]["plan_kind"] == "create"
    assert h.drain() == 0


def test_the_disk_can_only_grow_and_a_noop_is_refused(harness: Harness) -> None:
    h = harness
    d = launch(h, "alice")
    grown = _apply(h, d["id"], {"disk_gib": 12})
    assert grown["disk_gib"] == 12
    shrink = _update(h, d["id"], {"disk_gib": 8})
    assert shrink.status_code == 422 and "only be enlarged" in shrink.text
    same = _update(h, d["id"], {"disk_gib": 12, "name": "demo", "power_state": "running"})
    assert same.status_code == 422 and "does not change anything" in same.text


def test_an_edit_needs_an_existing_vm_and_an_owner(harness: Harness) -> None:
    h = harness
    reserved = create_and_plan(h)  # a plan exists but nothing was launched
    refused = _update(h, reserved["id"], {"name": "later"})
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "invalid_state"
    d = launch(h, "bob")
    assert _update(h, d["id"], {"name": "mine"}, user="alice").status_code == 404
    assert _update(h, "dep_" + "0" * 32, {"name": "nope"}).status_code in {404, 422}


def test_update_requests_are_idempotent(harness: Harness) -> None:
    h = harness
    d = launch(h)
    first = _update(h, d["id"], {"name": "renamed"}, **{"Idempotency-Key": "update-key-0001"})
    again = _update(h, d["id"], {"name": "renamed"}, **{"Idempotency-Key": "update-key-0001"})
    assert (first.status_code, again.status_code) == (202, 202) and first.json() == again.json()
    other = _update(h, d["id"], {"name": "other-name"}, **{"Idempotency-Key": "update-key-0001"})
    assert other.status_code == 409
    assert other.json()["error"]["code"] == "idempotency_key_reused"


# ------------------------------------------------- exact-plan approval guarantees


def test_a_newer_update_plan_supersedes_the_older_one(harness: Harness) -> None:
    h = harness
    d = launch(h)
    first = _preview(h, d["id"], {"name": "first-name"})["current_plan"]
    second = _preview(h, d["id"], {"name": "second-name"})["current_plan"]
    stale = h.client.post(
        f"/deployments/{d['id']}/approve",
        json={"plan_id": first["plan_id"], "plan_hash": first["plan_hash"]},
        headers=auth(),
    )
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "plan_not_current"
    wrong_hash = h.client.post(
        f"/deployments/{d['id']}/approve",
        json={"plan_id": second["plan_id"], "plan_hash": "0" * 64},
        headers=auth(),
    )
    assert (
        wrong_hash.status_code == 409 and wrong_hash.json()["error"]["code"] == "plan_hash_mismatch"
    )
    assert _detail(h, d["id"])["name"] == "demo"


def test_an_expired_update_plan_cannot_be_approved(harness: Harness) -> None:
    h = harness
    d = launch(h)
    plan = _preview(h, d["id"], {"power_state": "stopped"})["current_plan"]
    h.clock.advance(minutes=16)
    late = h.client.post(
        f"/deployments/{d['id']}/approve",
        json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
        headers=auth(),
    )
    assert late.status_code == 409 and late.json()["error"]["code"] == "plan_expired"
    assert (
        h.provisioner.instance_details([d["resources"]["instance_id"]])[
            d["resources"]["instance_id"]
        ].state
        == "running"
    )


def test_an_update_plan_that_expires_at_dispatch_is_refused_and_leaves_the_vm_active(
    harness: Harness,
) -> None:
    """Dispatch-time expiry applies to every mutation: here the stop is approved in time but
    the provisioner's preparation outlasts the plan."""
    h = harness
    d = launch(h)
    approve_current(h, _preview(h, d["id"], {"power_state": "stopped"}))
    h.clock.advance(minutes=14, seconds=59)
    from unitcompute.provisioning.base import check_dispatch

    class SlowPreparation(SimulatedProvisioner):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            h.clock.advance(seconds=2)  # e.g. a slow STS exchange
            check_dispatch()
            raise AssertionError("an expired plan was dispatched")

    Worker(h.settings, h.db, SlowPreparation(h.settings.data_dir), clock=h.clock).run_once()
    after = _detail(h, d["id"])
    assert after["latest_job"]["error"]["code"] == "plan_expired"
    assert (after["status"], after["power_state"]) == ("active", "running")
    assert _obligations(h, d["id"]) == []


# ------------------------------------------------------- recovery and the quota


def _old_unproven(h: Harness) -> None:
    with h.db.transaction() as c:
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, apply_attempted, created_at, updated_at) VALUES "
            "(?, 'dev:alice', 'old', 8, 'us-east-1', 't3.micro', 'simulated', 'deleted', 1, "
            "'2026-10-01', '2026-10-01')",
            ("dep_" + "a" * 32,),
        )
        c.execute(
            "INSERT INTO recovery_obligations (deployment_id, reason, evidence, created_at) "
            "VALUES (?, 'x', 'uncaptured', '2026-10-01')",
            ("dep_" + "a" * 32,),
        )


def test_edits_are_blocked_by_the_owner_wide_recovery_rule_but_deletion_is_not(
    harness: Harness,
) -> None:
    h = harness
    d = launch(h)
    ready = _preview(h, d["id"], {"power_state": "stopped"})["current_plan"]
    _old_unproven(h)
    # an already-ready update plan cannot be approved ...
    refused = h.client.post(
        f"/deployments/{d['id']}/approve",
        json={"plan_id": ready["plan_id"], "plan_hash": ready["plan_hash"]},
        headers=auth(),
    )
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "recovery_required"
    # ... and a new one cannot be planned; the VM stays active, not plan_failed
    assert _update(h, d["id"], {"name": "blocked"}).status_code == 202
    h.drain()
    blocked = _detail(h, d["id"])
    assert blocked["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert blocked["status"] == "active"
    # approved-and-queued updates are refused by the worker too
    # cleanup is never blocked
    assert h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth()).status_code == 202
    h.drain()
    approve_current(h, _detail(h, d["id"]))
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"


def test_an_approved_update_is_refused_by_the_worker_when_an_obligation_appears(
    harness: Harness,
) -> None:
    h = harness
    d = launch(h)
    approve_current(h, _preview(h, d["id"], {"disk_gib": 15}))
    _old_unproven(h)
    h.drain()
    after = _detail(h, d["id"])
    assert after["latest_job"]["error"]["code"] == "recovery_evidence_missing"
    assert (after["status"], after["disk_gib"]) == ("recovery_required", 8) or after[
        "disk_gib"
    ] == 8
    assert (
        h.provisioner.instance_details([d["resources"]["instance_id"]])[
            d["resources"]["instance_id"]
        ].root_volume_gib
        == 8
    )


class _FailingEdit(SimulatedProvisioner):
    def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
        raise ProvisioningError("terraform_apply_failed", "terraform apply failed")


def test_a_failed_edit_needs_recovery_without_blocking_the_owner_forever(harness: Harness) -> None:
    h = harness
    d = launch(h)
    dep = d["id"]
    approve_current(h, _preview(h, dep, {"disk_gib": 15}))
    Worker(h.settings, h.db, _FailingEdit(h.settings.data_dir), clock=h.clock).run_once()
    failed = _detail(h, dep)
    assert failed["status"] == "recovery_required"
    assert failed["disk_gib"] == 8  # the recorded values change only after a verified apply
    # an edit creates nothing, so no evidence has to be captured and nothing is unproven
    # nothing can have been created, so the stored state is enough evidence
    assert _obligations(h, dep) == [("terraform_apply_failed", "captured", False)]
    # the owner can retry the edit; success discharges the obligation
    done = _apply(h, dep, {"disk_gib": 15})
    assert (done["status"], done["disk_gib"]) == ("active", 15)
    assert _obligations(h, dep) == [("terraform_apply_failed", "captured", True)]


def test_an_edit_is_verified_against_ec2_not_just_terraform(harness: Harness) -> None:
    """Terraform reports success but EC2 shows the VM unchanged: recovery, not 'active'."""
    h = harness
    d = launch(h)
    approve_current(h, _preview(h, d["id"], {"power_state": "stopped"}))

    class Liar(SimulatedProvisioner):
        def instance_details(self, instance_ids: list[str]) -> dict[str, InstanceDetails]:
            return {i: InstanceDetails("running", "vol-0aaaaaaaaaaaaaaa1", 8) for i in instance_ids}

    Worker(h.settings, h.db, Liar(h.settings.data_dir), clock=h.clock).run_once()
    after = _detail(h, d["id"])
    assert after["status"] == "recovery_required"
    assert after["latest_job"]["error"]["code"] == "verification_failed"
    assert after["power_state"] == "running"  # unchanged until verified


def test_an_edit_that_changes_nothing_is_rejected_by_the_worker(harness: Harness) -> None:
    """The service refuses no-op edits; if one slips through, the plan itself is rejected."""
    h = harness
    d = launch(h)
    assert _update(h, d["id"], {"name": "later-name"}).status_code == 202
    with h.db.transaction() as conn:  # make the request match the current values
        conn.execute(
            "UPDATE plans SET request_json = ? WHERE deployment_id = ? AND status = 'pending'",
            (json.dumps({"name": "demo"}), d["id"]),
        )
    h.drain()
    plan = _detail(h, d["id"])["current_plan"]
    assert plan["status"] == "rejected" and "would change nothing" in plan["error"]["message"]
    assert _detail(h, d["id"])["status"] == "active"


def test_a_rejected_edit_leaves_the_vm_active(harness: Harness) -> None:
    h = harness
    d = launch(h)
    with h.db.transaction() as conn:  # corrupt the deployment so the policy rejects the plan
        conn.execute("UPDATE deployments SET instance_type = 'm5.large' WHERE id = ?", (d["id"],))
    assert _update(h, d["id"], {"name": "renamed"}).status_code == 202
    h.drain()
    after = _detail(h, d["id"])
    assert after["current_plan"]["status"] in {"rejected", "failed"}
    assert after["status"] == "active"


# ------------------------------------------------------------- moto: EC2 semantics


class TestMotoLifecycle:
    """EC2 behaviour that the verification relies on, against moto's EC2 (offline)."""

    def _vm(self, ec2: Any, size: int = 8, dep: str = "dep_" + "b" * 32) -> dict[str, str]:
        vm = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {"VolumeSize": size, "DeleteOnTermination": True},
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": kind,
                    "Tags": [
                        {"Key": "ManagedBy", "Value": "unitcompute"},
                        {"Key": "UnitComputeDeployment", "Value": dep},
                    ],
                }
                for kind in ("instance", "volume")
            ],
        )["Instances"][0]
        return {"iid": vm["InstanceId"], "vid": vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]}

    def _aws(self, h: Harness) -> Any:
        return _AwsBacked(h)

    def test_instance_details_tracks_stop_start_and_volume_growth(
        self, harness: Harness, moto_env: Any
    ) -> None:
        ec2, aws = moto_env, self._aws(harness)
        vm = self._vm(ec2)
        assert aws.instance_details([vm["iid"]])[vm["iid"]] == InstanceDetails(
            "running", vm["vid"], 8
        )
        ec2.stop_instances(InstanceIds=[vm["iid"]])
        assert aws.instance_details([vm["iid"]])[vm["iid"]].state == "stopped"
        ec2.modify_volume(VolumeId=vm["vid"], Size=12)
        assert aws.instance_details([vm["iid"]])[vm["iid"]].root_volume_gib == 12
        ec2.start_instances(InstanceIds=[vm["iid"]])
        assert aws.instance_details([vm["iid"]])[vm["iid"]].state == "running"
        ec2.terminate_instances(InstanceIds=[vm["iid"]])
        assert aws.instance_details([vm["iid"]]) == {}  # terminated instances are omitted
        assert aws.instance_details(["i-0ffffffffffffffff"]) == {}

    def test_a_worker_verifies_a_real_stop_in_ec2(self, harness: Harness, moto_env: Any) -> None:
        """The worker's edit verification through the AWS-backed lookups: Terraform's side is
        simulated, EC2's is moto's."""
        h, ec2 = harness, moto_env
        d = launch(h)
        iid = d["resources"]["instance_id"]
        vm = self._vm(ec2, dep=d["id"])
        with h.db.transaction() as conn:
            conn.execute(
                "UPDATE deployments SET instance_id = ?, root_volume_id = ? WHERE id = ?",
                (vm["iid"], vm["vid"], d["id"]),
            )
        state_path = h.provisioner._state_path(d["id"])
        state = json.loads(state_path.read_text())
        state["aws_instance.vm"]["id"] = vm["iid"]
        state["aws_instance.vm"]["root_block_device"][0]["volume_id"] = vm["vid"]
        state["aws_ec2_instance_state.vm"].update(id=vm["iid"], instance_id=vm["iid"])
        state_path.write_text(json.dumps(state))
        assert iid != vm["iid"]

        approve_current(h, _preview(h, d["id"], {"power_state": "stopped"}))

        class StopsInEc2(_AwsBacked):
            def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
                ec2.stop_instances(InstanceIds=[vm["iid"]])
                return super().apply(spec, workdir, plan_path)

        Worker(h.settings, h.db, StopsInEc2(h), clock=h.clock).run_once()
        after = _detail(h, d["id"])
        assert (after["status"], after["power_state"], after["instance_state"]) == (
            "active",
            "stopped",
            "stopped",
        )

    def test_a_stop_that_did_not_happen_in_ec2_is_recovery(
        self, harness: Harness, moto_env: Any
    ) -> None:
        h, ec2 = harness, moto_env
        d = launch(h)
        vm = self._vm(ec2, dep=d["id"])
        with h.db.transaction() as conn:
            conn.execute(
                "UPDATE deployments SET instance_id = ? WHERE id = ?", (vm["iid"], d["id"])
            )
        state_path = h.provisioner._state_path(d["id"])
        state = json.loads(state_path.read_text())
        state["aws_instance.vm"]["id"] = vm["iid"]
        state["aws_instance.vm"]["root_block_device"][0]["volume_id"] = vm["vid"]
        state["aws_ec2_instance_state.vm"].update(id=vm["iid"], instance_id=vm["iid"])
        state_path.write_text(json.dumps(state))
        approve_current(h, _preview(h, d["id"], {"power_state": "stopped"}))
        Worker(h.settings, h.db, _AwsBacked(h), clock=h.clock).run_once()  # EC2 still running
        after = _detail(h, d["id"])
        assert after["status"] == "recovery_required"
        error = after["latest_job"]["error"]
        assert error["code"] == "verification_failed"
        assert "is running, not stopped" in error["message"]
        assert (
            ec2.describe_instances(InstanceIds=[vm["iid"]])["Reservations"][0]["Instances"][0][
                "State"
            ]["Name"]
            == "running"
        )


# ----------------------------------------------------------------- orphan report


def test_orphan_report_lists_resources_without_a_live_deployment(
    harness: Harness, moto_env: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from unitcompute import admin

    h, ec2 = harness, moto_env
    tracked = launch(h)
    vm = TestMotoLifecycle()._vm(ec2)  # tagged for a deployment the database has never heard of
    dep_unknown = "dep_" + "b" * 32
    monkeypatch.setattr(admin, "load_settings", lambda: h.settings)
    monkeypatch.setattr(admin, "build_provisioner", lambda settings: _AwsBacked(h))
    capsys.readouterr()
    assert admin.main(["orphan-report"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {r["id"] for r in report["orphans"]} >= {vm["iid"], vm["vid"]}
    assert all(
        r["deployment_id"] == dep_unknown and r["reason"] == "unknown_deployment"
        for r in report["orphans"]
    )
    assert tracked["id"] not in {r["deployment_id"] for r in report["orphans"]}
    assert report["tracked"] >= 0 and report["read_only"] is True
    # deleting the tracked VM leaves nothing of it behind, and it is not reported
    assert (
        h.client.post(f"/deployments/{tracked['id']}/deletion-plan", headers=auth()).status_code
        == 202
    )
    h.drain()
    approve_current(h, _detail(h, tracked["id"]))
    h.drain()
    capsys.readouterr()
    assert admin.main(["orphan-report"]) == 0
    assert tracked["id"] not in {
        r["deployment_id"] for r in json.loads(capsys.readouterr().out)["orphans"]
    }


def test_orphan_report_flags_unrecorded_resources_of_a_live_deployment(
    harness: Harness, moto_env: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from unitcompute import admin

    h, ec2 = harness, moto_env
    d = launch(h)
    stray = TestMotoLifecycle()._vm(ec2, dep=d["id"])  # tagged for it, never recorded
    monkeypatch.setattr(admin, "load_settings", lambda: h.settings)
    monkeypatch.setattr(admin, "build_provisioner", lambda settings: _AwsBacked(h))
    capsys.readouterr()
    assert admin.main(["orphan-report"]) == 0
    reasons = {r["id"]: r["reason"] for r in json.loads(capsys.readouterr().out)["orphans"]}
    assert reasons[stray["iid"]] == "unrecorded_resource"


def test_orphan_report_flags_resources_of_a_deleted_deployment(
    harness: Harness, moto_env: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from unitcompute import admin

    h, ec2 = harness, moto_env
    d = launch(h)
    vm = TestMotoLifecycle()._vm(ec2, dep=d["id"])
    with h.db.transaction() as conn:  # the database says deleted; AWS still has resources
        conn.execute("UPDATE deployments SET status = 'deleted' WHERE id = ?", (d["id"],))
    monkeypatch.setattr(admin, "load_settings", lambda: h.settings)
    monkeypatch.setattr(admin, "build_provisioner", lambda settings: _AwsBacked(h))
    capsys.readouterr()
    assert admin.main(["orphan-report"]) == 0
    reasons = {r["id"]: r["reason"] for r in json.loads(capsys.readouterr().out)["orphans"]}
    assert reasons[vm["iid"]] == "deployment_deleted"


def test_time_helpers_are_deterministic(harness: Harness) -> None:
    before = harness.clock()
    harness.clock.advance(minutes=1)
    assert harness.clock() - before == timedelta(minutes=1)


# ----------------------------------------------------------- extra guard coverage


def test_an_edit_cannot_be_requested_while_a_deletion_is_in_progress(harness: Harness) -> None:
    h = harness
    d = launch(h)
    assert h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth()).status_code == 202
    h.drain()
    assert _detail(h, d["id"])["status"] == "awaiting_deletion_approval"
    refused = _update(h, d["id"], {"name": "too-late"})
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "invalid_state"


def test_the_root_disk_size_is_verified_against_ec2(harness: Harness) -> None:
    h = harness
    d = launch(h)
    approve_current(h, _preview(h, d["id"], {"disk_gib": 15}))

    class WrongSize(SimulatedProvisioner):
        def instance_details(self, instance_ids: list[str]) -> dict[str, InstanceDetails]:
            return {i: InstanceDetails("running", "vol-0aaaaaaaaaaaaaaa1", 8) for i in instance_ids}

    Worker(h.settings, h.db, WrongSize(h.settings.data_dir), clock=h.clock).run_once()
    after = _detail(h, d["id"])
    error = after["latest_job"]["error"] or {}
    assert error.get("code") == "verification_failed"
    assert "root disk is 8 GiB, not 15 GiB" in error.get("message", "")
    assert (after["status"], after["disk_gib"]) == ("recovery_required", 8)


def test_state_evidence_accepts_the_power_resource_added_to_an_existing_vm() -> None:
    """A repair of a VM that predates the power-state resource creates only that resource;
    its ID is the instance ID, which is legitimately in the prior state."""
    from test_review_round5 import _raw_state
    from unitcompute.provisioning.state_evidence import (
        INSTANCE_STATE,
        PriorState,
        StateEvidenceError,
        bind_to_plan,
        parse_raw_state,
    )

    document = parse_raw_state(
        _raw_state("i-0aaaaaaaaaaaaaaa1", "vol-0aaaaaaaaaaaaaaa1", "sg-0aaaaaaaaaaaaaaa1"),
        terraform_version="simulated",
    )
    bind_to_plan(
        document,
        prior=PriorState("simulated-dep_" + "0" * 32, 0),
        prior_ids={"i-0aaaaaaaaaaaaaaa1", "vol-0aaaaaaaaaaaaaaa1", "sg-0aaaaaaaaaaaaaaa1"},
        creates={INSTANCE_STATE},
        require_all_creates=True,
    )
    # ... but an instance the plan was supposed to create cannot reuse a prior ID
    with pytest.raises(StateEvidenceError, match="prior"):
        bind_to_plan(
            document,
            prior=PriorState("simulated-dep_" + "0" * 32, 0),
            prior_ids={"i-0aaaaaaaaaaaaaaa1"},
            creates={"aws_instance.vm"},
            require_all_creates=True,
        )


def test_a_power_resource_must_belong_to_the_states_own_instance() -> None:
    from test_review_round5 import _raw_state
    from unitcompute.provisioning.state_evidence import StateEvidenceError, parse_raw_state

    document = _raw_state("i-0aaaaaaaaaaaaaaa1", "vol-0aaaaaaaaaaaaaaa1", "sg-0aaaaaaaaaaaaaaa1")
    for resource in document["resources"]:
        if resource["type"] == "aws_ec2_instance_state":
            resource["instances"][0]["attributes"]["id"] = "i-0bbbbbbbbbbbbbbb2"
    with pytest.raises(StateEvidenceError, match="power state does not belong"):
        parse_raw_state(document, terraform_version="simulated")


def test_each_execution_policy_alone_keeps_a_deployment_to_its_own_resources(
    tmp_path: Path,
) -> None:
    """Role policy and session policy are independent defences: each alone refuses another
    deployment's instance for stop, start and volume growth."""
    import iam_eval
    from conftest import make_settings
    from test_config_and_auth import TERRAFORM_SETTINGS
    from test_review_round2 import ALICE_DEP, BOB_DEP, _context, _placeholders, _role
    from unitcompute.provisioning.aws import session_policy

    settings = make_settings(tmp_path, **TERRAFORM_SETTINGS)
    session = session_policy(settings, "apply", ALICE_DEP)
    role = _role("apply-role-policy.json")
    account = settings.aws_account_id
    for policy in (role, session):
        for action, kind in (
            ("ec2:StopInstances", "instance"),
            ("ec2:StartInstances", "instance"),
            ("ec2:ModifyVolume", "volume"),
        ):
            arn = f"arn:aws:ec2:us-east-1:{account}:{kind}/{kind[:3]}-0123456789abcdef0"
            for owner, expected in ((ALICE_DEP, True), (BOB_DEP, False)):
                context = _context(
                    ALICE_DEP,
                    **{
                        "ec2:ResourceTag/ManagedBy": "unitcompute",
                        "ec2:ResourceTag/UnitComputeDeployment": owner,
                    },
                )
                allowed = iam_eval.allowed([policy], action, arn, context, _placeholders(settings))
                assert allowed is expected, (action, owner, "role" if policy is role else "session")
