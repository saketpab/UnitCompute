"""Regressions for the fifth independent review round of 33602aa.

Adapted from security5 ``test_security5_independent.py``, reliability5
``test_reliability5_independent.py`` and ``reproduce_backend_failure.py``. IDs match
docs/verification-ledger.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from conftest import FakeClock, Harness, approve_current, auth, create_and_plan, launch
from test_review_round2 import (
    _AwsBacked,
    _client,
    _detail,
    _replan,
    _restore_terraform_state,
    _schema_v1_deployment,
)
from unitcompute.agent.fake import ScriptedChatModel
from unitcompute.agent.service import AgentService
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.errors import ServiceUnavailable
from unitcompute.identities import IdentityLedger, identity
from unitcompute.provisioning.base import ApplyResult, ProvisioningError
from unitcompute.provisioning.simulated import SimulatedProvisioner, raw_state, simulated_lineage
from unitcompute.provisioning.state_evidence import (
    AppliedState,
    StateEvidenceError,
    parse_raw_state,
)
from unitcompute.schemas import AgentMessageRequest
from unitcompute.worker import Worker

ALICE = Principal(subject="dev:alice", auth_method="dev")
TERRAFORM = shutil.which("terraform") or str(Path.home() / ".local/bin/terraform")


def _obligations(h: Any, dep: str) -> list[tuple[str, str, bool]]:
    with h.db.read() as conn:
        return [
            (r["reason"], r["evidence"], r["discharged_at"] is not None)
            for r in conn.execute(
                "SELECT * FROM recovery_obligations WHERE deployment_id = ? ORDER BY id", (dep,)
            )
        ]


def _quota_held(client: Any, user: str = "alice") -> bool:
    response = client.post("/deployments", json={"name": "next", "disk_gib": 8}, headers=auth(user))
    return bool(response.status_code == 409)


def _raw_state(
    iid: str | None,
    vid: str | None,
    sg: str | None = None,
    *,
    dep: str = "dep_" + "0" * 32,
    terraform_version: str = "simulated",
) -> dict[str, Any]:
    """A complete raw state envelope (round 6), bound to ``dep``'s simulated lineage."""
    resources: dict[str, dict[str, Any]] = {}
    if iid:
        resources["aws_instance.vm"] = {"id": iid, "root_block_device": [{"volume_id": vid}]}
    if iid:
        resources["aws_ec2_instance_state.vm"] = {"id": iid, "instance_id": iid, "state": "running"}
    if sg:
        resources["aws_security_group.vm"] = {"id": sg}
    return raw_state(simulated_lineage(dep), 1, resources, terraform_version)


# ---------------------------------- R5-1: refreshed state is not launch evidence


def test_r5_1_refreshed_state_with_replacement_does_not_complete_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Both reviewers: refreshed prior_state names the replacement; the detached original
    must keep repair/deletion blocked."""
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, original = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    ec2.stop_instances(InstanceIds=[iid])
    ec2.detach_volume(VolumeId=original, InstanceId=iid, Device="/dev/sda1")
    replacement = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=replacement, InstanceId=iid, Device="/dev/sda1")
    client, h = _client(settings, db, FakeClock())
    with client:
        _restore_terraform_state(h, dep, iid, replacement)
        for route in ("deletion-plan", "plan"):
            _, pending = _replan(h, _AwsBacked(h), dep, route)
            assert pending["status"] == "plan_failed"
            assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        with db.read() as conn:
            known = IdentityLedger.known(conn, dep)
        assert known.launch_roots == {}
        assert replacement in known.observed_roots[iid]
        assert ec2.describe_volumes(VolumeIds=[original])["Volumes"][0]["State"] == "available"
        assert _quota_held(client)


def test_r5_1_repair_outputs_of_existing_instance_are_not_launch_evidence(
    harness: Harness,
) -> None:
    """A repair apply that did not create the instance reports its current (refreshed) root;
    that must not become launch evidence or overwrite the deployment's launch root."""
    h = harness
    d = launch(h)
    launch_root = d["resources"]["root_volume_id"]
    h.client.post(f"/deployments/{d['id']}/plan", headers=auth())
    h.drain()
    pending = _detail(h, d["id"])
    assert pending["current_plan"]["resource_changes"] == []  # instance is a no-op

    class ReportsReplacement(SimulatedProvisioner):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            result = super().apply(spec, workdir, plan_path)
            return ApplyResult(
                outputs={**result.outputs, "root_volume_id": "vol-0fffffffffffffff9"}
            )

    approve_current(h, pending)
    Worker(h.settings, h.db, ReportsReplacement(h.settings.data_dir), clock=h.clock).run_once()
    with h.db.read() as conn:
        known = IdentityLedger.known(conn, d["id"])
        row_root = conn.execute(
            "SELECT root_volume_id FROM deployments WHERE id = ?", (d["id"],)
        ).fetchone()[0]
    instance = d["resources"]["instance_id"]
    assert known.launch_roots[instance] == {launch_root}
    assert "vol-0fffffffffffffff9" in known.observed_roots[instance]
    assert row_root == launch_root


def test_r5_1_legacy_root_ids_need_single_create_history(harness: Harness) -> None:
    """Legacy root sources (written without launch provenance) count only when job history
    shows one successful create apply; otherwise they may be a later refreshed value."""
    d = launch(harness)
    dep, iid = d["id"], d["resources"]["instance_id"]
    harness.worker().record_identities(
        dep, [identity("vol-0aaaaaaaaaaaaaaa7", "apply_output", iid)]
    )
    with harness.db.read() as conn:
        assert "vol-0aaaaaaaaaaaaaaa7" in IdentityLedger.known(conn, dep).launch_roots[iid]
    with harness.db.transaction() as conn:  # model a second successful create apply
        job = conn.execute(
            "SELECT * FROM jobs WHERE deployment_id = ? AND kind = 'apply'", (dep,)
        ).fetchone()
        conn.execute(
            "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
            "payload_hash, created_at) VALUES ('job_second', ?, ?, ?, 'apply', 'succeeded', "
            "'h', 'now')",
            (job["owner_id"], dep, job["plan_id"]),
        )
    with harness.db.read() as conn:
        known = IdentityLedger.known(conn, dep)
    assert "vol-0aaaaaaaaaaaaaaa7" not in known.launch_roots.get(iid, set())
    assert "vol-0aaaaaaaaaaaaaaa7" in known.observed_roots[iid]


# ---------------------- R5-2: failed applies leave durable, evidence-backed obligations


class _BackendWriteFailure(_AwsBacked):
    """Creates a real (moto) VM, then fails like Terraform's backend write, leaving
    errored.tfstate in the plan's work directory."""

    def __init__(self, h: Any, ec2: Any, errored: bool = True) -> None:
        super().__init__(h)
        self.ec2, self.errored, self.created = ec2, errored, {}

    def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
        tags = [
            {"Key": "UnitComputeDeployment", "Value": spec.deployment_id},
            {"Key": "ManagedBy", "Value": "unitcompute"},
        ]
        vm = self.ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            BlockDeviceMappings=[
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": True}}
            ],
            TagSpecifications=[{"ResourceType": k, "Tags": tags} for k in ("instance", "volume")],
        )["Instances"][0]
        self.created = {
            "iid": vm["InstanceId"],
            "vid": vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"],
        }
        if self.errored:
            (workdir / "errored.tfstate").write_text(
                json.dumps(
                    _raw_state(self.created["iid"], self.created["vid"], dep=spec.deployment_id)
                )
            )
        raise ProvisioningError("terraform_apply_failed", "Failed to save state")

    def capture_stored_state(self, spec: Any, workdir: Path) -> dict[str, Any]:
        raise ProvisioningError("state_capture_failed", "backend unreachable")


def test_r5_2_errored_state_is_captured_and_blocks_false_deletion(
    harness: Harness, moto_env: Any
) -> None:
    """Both reviewers: tags removed and VM terminated after a backend-write failure; the
    retained errored.tfstate still identifies the surviving disk."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    dep = d["id"]
    approve_current(h, d)
    failing = _BackendWriteFailure(h, ec2)
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    iid, vid = failing.created["iid"], failing.created["vid"]
    assert _detail(h, dep)["status"] == "recovery_required"
    assert _obligations(h, dep) == [("terraform_apply_failed", "captured", False)]
    with h.db.read() as conn:
        assert IdentityLedger.known(conn, dep).launch_roots == {iid: {vid}}
    ec2.modify_instance_attribute(
        InstanceId=iid,
        BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"DeleteOnTermination": False}}],
    )
    ec2.delete_tags(Resources=[vid], Tags=[{"Key": "UnitComputeDeployment"}])
    ec2.terminate_instances(InstanceIds=[iid])
    recovery = h.settings.workdir_root / dep / d["current_plan"]["plan_id"] / "errored.tfstate"
    _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
    assert pending["current_plan"]["status"] == "rejected"  # live disk outside state
    assert vid in pending["current_plan"]["error"]["message"]
    h.clock.advance(days=8)
    h.worker().housekeeping()
    assert recovery.exists()
    assert _quota_held(h.client)
    # Once the disk is really gone, deletion can be verified and the obligation discharged.
    ec2.delete_volume(VolumeId=vid)
    _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
    approve_current(h, pending)
    Worker(h.settings, h.db, _AwsBacked(h), clock=h.clock).run_once()
    assert _detail(h, dep)["status"] == "deleted"
    assert _obligations(h, dep) == [("terraform_apply_failed", "captured", True)]
    h.clock.advance(days=8)
    h.worker().housekeeping()
    assert not recovery.parent.exists()


def test_r5_2_uncaptured_failed_apply_blocks_everything_and_is_never_discharged(
    harness: Harness, moto_env: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """Fail closed: the apply could have created resources, and neither errored nor stored
    state can be read. Empty plans/applies cannot discharge it; evidence is never pruned."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    dep = d["id"]
    approve_current(h, d)
    Worker(h.settings, h.db, _BackendWriteFailure(h, ec2, errored=False), clock=h.clock).run_once()
    assert _obligations(h, dep) == [("terraform_apply_failed", "uncaptured", False)]
    for route in ("deletion-plan", "plan"):
        _, pending = _replan(h, _AwsBacked(h), dep, route)
        assert pending["status"] == "recovery_required"
        assert pending["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    workdir = h.settings.workdir_root / dep / d["current_plan"]["plan_id"]
    h.clock.advance(days=30)
    h.worker().housekeeping()
    assert workdir.exists()
    assert _quota_held(h.client)
    with h.db.transaction() as conn:  # a later "success" cannot discharge it either
        conn.execute(
            "UPDATE recovery_obligations SET discharged_at = 'now' WHERE deployment_id = ? "
            "AND evidence IN ('captured', 'not_needed')",
            (dep,),
        )
    assert _obligations(h, dep) == [("terraform_apply_failed", "uncaptured", False)]
    from unitcompute import admin  # the operator report shows the open obligation

    monkeypatch.setattr(admin, "load_settings", lambda: h.settings)
    capsys.readouterr()
    assert admin.main(["recovery-report"]) == 0
    (entry,) = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [(o["reason"], o["evidence"]) for o in entry["open_recovery_obligations"]] == [
        ("terraform_apply_failed", "uncaptured")
    ]


def test_r5_2_stored_state_capture_recovers_evidence(harness: Harness, moto_env: Any) -> None:
    """No errored.tfstate, but the apply's stored state can be read without refresh."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)
    failing = _BackendWriteFailure(h, ec2, errored=False)

    def stored(spec: Any, workdir: Path) -> dict[str, Any]:
        # Round 6: stored state is accepted only if it shows every resource the plan creates.
        return _raw_state(
            failing.created["iid"],
            failing.created["vid"],
            "sg-0123456789abcdef0",
            dep=spec.deployment_id,
        )

    failing.capture_stored_state = stored  # type: ignore[method-assign]
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "captured", False)]
    with h.db.read() as conn:
        known = IdentityLedger.known(conn, d["id"])
    assert known.launch_roots == {failing.created["iid"]: {failing.created["vid"]}}


def _crash_mid_create_apply(h: Harness, write_errored: bool) -> tuple[dict[str, Any], str]:
    """The worker claims the apply, Terraform creates the VM, then the worker dies."""
    d = create_and_plan(h)
    approve_current(h, d)
    job = h.worker().claim()
    assert job is not None
    with h.db.read() as conn:
        row = conn.execute("SELECT * FROM deployments WHERE id = ?", (d["id"],)).fetchone()
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (job["plan_id"],)).fetchone()
    plan_path = Path(plan["plan_path"])
    outputs = h.provisioner.apply(Worker._spec(row), plan_path.parent, plan_path).outputs
    if write_errored:
        (plan_path.parent / "errored.tfstate").write_text(
            json.dumps(_raw_state(outputs["instance_id"], outputs["root_volume_id"], dep=d["id"]))
        )
    return d, job["id"]


def test_r5_2_crash_mid_apply_without_errored_state_fails_closed(harness: Harness) -> None:
    """After a crash it is unknown whether Terraform persisted its final state, so the
    stored state is not trusted, even though it happens to be complete here."""
    h = harness
    d, job_id = _crash_mid_create_apply(h, write_errored=False)
    successor = Worker(h.settings, h.db, h.provisioner, clock=h.clock, worker_id="w-new")
    assert successor.recover_interrupted() == [job_id]
    assert _obligations(h, d["id"]) == [("worker_interrupted", "uncaptured", False)]
    _, pending = _replan(h, h.provisioner, d["id"], "deletion-plan")
    assert pending["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert _quota_held(h.client)


def test_r5_2_crash_mid_apply_with_errored_state_is_captured(harness: Harness) -> None:
    h = harness
    d, job_id = _crash_mid_create_apply(h, write_errored=True)
    successor = Worker(h.settings, h.db, h.provisioner, clock=h.clock, worker_id="w-new")
    assert successor.recover_interrupted() == [job_id]
    assert _obligations(h, d["id"]) == [("worker_interrupted", "captured", False)]
    with h.db.read() as conn:
        assert IdentityLedger.known(conn, d["id"]).instances_without_root_disk() == []
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    h.drain()
    approve_current(h, _detail(h, d["id"]))
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"
    assert _obligations(h, d["id"]) == [("worker_interrupted", "captured", True)]


def test_r5_2_later_retry_never_trusts_stored_state(harness: Harness, moto_env: Any) -> None:
    """Reviewers' scenario: backend state empty after the failure. A later preview must not
    read that empty stored state as 'nothing was created'."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)
    Worker(h.settings, h.db, _BackendWriteFailure(h, ec2, errored=False), clock=h.clock).run_once()
    _, pending = _replan(h, _AwsBacked(h), d["id"], "deletion-plan")  # empty stored state
    assert pending["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "uncaptured", False)]


def test_r5_2_failed_delete_without_capture_does_not_block(harness: Harness) -> None:
    """A destroy cannot create resources, so a failed one needs no new evidence."""
    h = harness
    d = launch(h)
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    h.drain()

    class FailingDestroy(SimulatedProvisioner):
        def apply(self, *args: Any) -> ApplyResult:
            raise ProvisioningError("terraform_apply_failed", "throttled")

        def capture_stored_state(self, spec: Any, workdir: Path) -> dict[str, Any]:
            raise ProvisioningError("state_capture_failed", "unreachable")

    approve_current(h, _detail(h, d["id"]))
    Worker(h.settings, h.db, FailingDestroy(h.settings.data_dir), clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "not_needed", False)]
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    h.drain()
    approve_current(h, _detail(h, d["id"]))
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"


def test_r5_2_obligation_rows_only_move_forward(harness: Harness) -> None:
    d = create_and_plan(harness)
    with harness.db.transaction() as conn:
        for evidence in ("uncaptured", "captured"):
            conn.execute(
                "INSERT INTO recovery_obligations (deployment_id, reason, evidence, created_at) "
                "VALUES (?, 'test', ?, 'now')",
                (d["id"], evidence),
            )
    for statement in (
        "DELETE FROM recovery_obligations",
        "UPDATE recovery_obligations SET discharged_at = 'now' WHERE evidence = 'uncaptured'",
        "UPDATE recovery_obligations SET evidence = 'not_needed' WHERE evidence = 'uncaptured'",
        "UPDATE recovery_obligations SET evidence = 'uncaptured' WHERE evidence = 'captured'",
    ):
        conn = harness.db.connect()
        try:
            with pytest.raises(sqlite3.IntegrityError, match="recovery obligations"):
                conn.execute(statement)
        finally:
            conn.close()
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE recovery_obligations SET discharged_at = 'now' WHERE evidence = 'captured'"
        )
    conn = harness.db.connect()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE recovery_obligations SET discharged_at = 'later' "
                "WHERE evidence = 'captured'"
            )
    finally:
        conn.close()


def test_r5_2_migration_backfills_obligations_for_earlier_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from conftest import make_settings

    settings = make_settings(tmp_path)
    db = Database(settings.database_path)
    migrations = database._migration_files()
    with monkeypatch.context() as m:
        m.setattr(database, "_migration_files", lambda: migrations[:4])
        assert db.migrate() == [1, 2, 3, 4]
    now = "2026-10-30T00:00:00+00:00"
    with db.transaction() as conn:
        for dep, later_success in (("dep_" + "1" * 32, False), ("dep_" + "2" * 32, True)):
            conn.execute(
                "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
                "provisioner, status, created_at, updated_at) VALUES (?, ?, 'demo', 8, "
                "'us-east-1', 't3.micro', 'simulated', 'recovery_required', ?, ?)",
                (dep, "dev:" + dep[4:8], now, now),
            )
            plan = "plan_" + dep[4:]
            conn.execute(
                "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
                "config_hash, region, state_key, template_version, created_at) VALUES "
                "(?, ?, 'dev:a', 'create', 'apply_failed', 'simulated', 'h', 'us-east-1', 'k', "
                "'v', ?)",
                (plan, dep, now),
            )
            conn.execute(
                "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
                "payload_hash, created_at) VALUES (?, 'dev:a', ?, ?, 'apply', "
                "'recovery_required', 'h', ?)",
                ("job_" + dep[4:], dep, plan, now),
            )
            if later_success:
                conn.execute(
                    "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
                    "config_hash, region, state_key, template_version, created_at) VALUES "
                    "(?, ?, 'dev:a', 'create', 'applied', 'simulated', 'h', 'us-east-1', 'k', "
                    "'v', ?)",
                    ("plan_ok" + dep[4:], dep, now),
                )
                conn.execute(
                    "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
                    "payload_hash, created_at) VALUES (?, 'dev:a', ?, ?, 'apply', "
                    "'succeeded', 'h', ?)",
                    ("job_ok" + dep[4:], dep, "plan_ok" + dep[4:], now),
                )
    assert db.migrate() == [5, 6, 7, 8]
    with db.read() as conn:
        rows = sorted(
            (r["deployment_id"], r["reason"], r["evidence"], r["discharged_at"] is not None)
            for r in conn.execute("SELECT * FROM recovery_obligations")
        )
    # Round 6: a later success does not resolve the failed apply; it is revalidated.
    assert rows == [
        ("dep_" + "1" * 32, "legacy_unresolved_apply", "uncaptured", False),
        ("dep_" + "2" * 32, "evidence_revalidation", "uncaptured", False),
        ("dep_" + "2" * 32, "legacy_resolved_apply", "not_needed", True),
    ]


# ------------------------------------------- R5-2: real Terraform backend failure


@pytest.mark.terraform
def test_r5_2_real_terraform_backend_failure_leaves_errored_state(tmp_path: Path) -> None:
    """Reviewer reproduction with the production TerraformProvisioner and runner: a
    failing localhost HTTP backend makes Terraform 1.17.1 write errored.tfstate. Our
    reader parses its format, and fails closed on its (non-template) resource."""
    if not Path(TERRAFORM).exists():
        pytest.skip("terraform binary not installed")
    from unitcompute.config import Settings
    from unitcompute.provisioning.aws import TemporaryCredentials
    from unitcompute.provisioning.base import DeploymentSpec
    from unitcompute.provisioning.runner import TerraformRunner
    from unitcompute.provisioning.terraform import TerraformProvisioner

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    work = tmp_path / "work"
    work.mkdir()
    (work / "main.tf").write_text(
        'terraform {\n  backend "http" {}\n}\nresource "terraform_data" "vm" {\n'
        '  input = "i-0123456789abcdef0"\n}\noutput "instance_id" {\n'
        "  value = terraform_data.vm.output\n}\n"
    )
    runner = TerraformRunner(
        Path(TERRAFORM),
        plugin_cache_dir=Path(os.environ["TF_PLUGIN_CACHE_DIR"])
        if os.environ.get("TF_PLUGIN_CACHE_DIR")
        else None,
    )
    env = runner.base_env(work)
    try:
        for args in (
            [
                "init",
                "-input=false",
                "-no-color",
                f"-backend-config=address=http://127.0.0.1:{server.server_port}/state",
                "-backend-config=retry_max=0",
            ],
            ["plan", "-input=false", "-no-color", "-out=tfplan"],
        ):
            assert (
                runner.run(args, workdir=work, env=env, timeout=120, log_name=args[0]).returncode
                == 0
            )

        class FakeAws:
            def credentials(self, *args: Any) -> TemporaryCredentials:
                return TemporaryCredentials("synthetic", "synthetic", "synthetic")

        provisioner = TerraformProvisioner(Settings(data_dir=tmp_path / "data"), runner, FakeAws())  # type: ignore[arg-type]
        spec = DeploymentSpec("dep_" + "a" * 32, "owner", "demo", 8, "us-east-1", "t3.micro")
        with pytest.raises(ProvisioningError) as exc:
            provisioner.apply(spec, work, work / "tfplan")
        assert exc.value.code == "terraform_apply_failed"
    finally:
        server.shutdown()
        server.server_close()
    errored = json.loads((work / "errored.tfstate").read_text())
    assert errored["version"] == 4
    assert errored["outputs"]["instance_id"]["value"] == "i-0123456789abcdef0"
    with pytest.raises(StateEvidenceError, match=r"unexpected resource terraform_data\.vm"):
        parse_raw_state(errored, terraform_version="1.17.1")


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (
            _raw_state("i-0aaaaaaaaaaaaaaa1", "vol-0aaaaaaaaaaaaaaa1", "sg-0aaaaaaaaaaaaaaa1"),
            AppliedState(
                "i-0aaaaaaaaaaaaaaa1",
                "sg-0aaaaaaaaaaaaaaa1",
                "vol-0aaaaaaaaaaaaaaa1",
                "i-0aaaaaaaaaaaaaaa1",
            ),
        ),
        (_raw_state(None, None), AppliedState(None, None, None)),
    ],
)
def test_r5_2_raw_state_reader_accepts_template_state(
    document: dict[str, Any], expected: AppliedState
) -> None:
    assert parse_raw_state(document, terraform_version="simulated").applied == expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(version=3),
        lambda d: d["resources"][0].update(module="module.x"),
        lambda d: d["resources"][0]["instances"][0].update(index_key=0),
        lambda d: d["resources"][0].update(mode="data"),
        lambda d: d["resources"][0].update(type="aws_ebs_volume"),
        lambda d: d["resources"][0]["instances"].append(d["resources"][0]["instances"][0]),
        lambda d: d["resources"].append(d["resources"][0]),
        lambda d: d["resources"][0]["instances"][0]["attributes"].update(id="i-x"),
        lambda d: d["resources"][0]["instances"][0]["attributes"].update(root_block_device=[]),
        lambda d: d["resources"][0]["instances"][0]["attributes"].update(
            root_block_device=[
                {"volume_id": "vol-1aaaaaaaaaaaaaaa"},
                {"volume_id": "vol-2aaaaaaaaaaaaaaa"},
            ]
        ),
    ],
)
def test_r5_2_raw_state_reader_fails_closed(mutate: Any) -> None:
    document = _raw_state("i-0aaaaaaaaaaaaaaa1", "vol-0aaaaaaaaaaaaaaa1")
    mutate(document)
    with pytest.raises(StateEvidenceError):
        parse_raw_state(document, terraform_version="simulated")


# ------------------------------- R5-3: corrupt evidence is isolated, never fatal


def test_r5_3_malformed_evidence_does_not_stop_worker_recovery(harness: Harness) -> None:
    """Reliability reproduction: a JSON null record used to crash startup recovery."""
    h = harness
    broken = create_and_plan(h, "alice")
    healthy = create_and_plan(h, "bob")
    approve_current(h, broken, "alice")
    job = h.worker().claim()  # alice's apply is running when the worker dies
    assert job is not None
    approve_current(h, healthy, "bob")
    (h.settings.workdir_root / broken["id"] / "identities.jsonl").write_text(
        'null\n[1]\n{"id": 5, "source": "x"}\n{"id": "i-0aaaaaaaaaaaaaaa1", "source": "BAD"}\n'
    )
    worker = h.worker()
    assert worker.recover_interrupted() == [job["id"]]  # does not raise
    assert worker.run_once()  # the unrelated deployment's job still runs
    assert _detail(h, broken["id"])["latest_job"]["status"] == "recovery_required"
    bob = h.client.get(f"/deployments/{healthy['id']}", headers=auth("bob")).json()
    assert bob["status"] == "active"
    assert ("evidence_file_corrupt", "uncaptured", False) in _obligations(h, broken["id"])
    _, pending = _replan(h, h.provisioner, broken["id"], "deletion-plan")
    assert pending["current_plan"]["error"]["code"] == "recovery_evidence_missing"


def test_r5_3_torn_record_marks_only_that_deployment(harness: Harness) -> None:
    d = create_and_plan(harness)
    path = harness.settings.workdir_root / d["id"] / "identities.jsonl"
    path.write_text('{"id":"i-0aaaaaaaaaaaaaaa1","source":')
    harness.worker().import_identities(d["id"])
    assert _obligations(harness, d["id"]) == [("evidence_file_corrupt", "uncaptured", False)]
    harness.worker().import_identities(d["id"])  # not duplicated
    assert len(_obligations(harness, d["id"])) == 1


# ------------------------------------ R5-4: every creator syncs directory entries


def test_r5_4_worker_created_evidence_ancestors_are_synced(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reliability reproduction: worker-created directories plus contention (evidence file
    is the only fallback). The work root and data directory entries must be synced."""
    h = harness
    synced: list[Path] = []
    real_fsync = os.fsync

    def trace(fd: int) -> None:
        synced.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        real_fsync(fd)

    monkeypatch.setattr("unitcompute.durable.os.fsync", trace)
    monkeypatch.setattr("unitcompute.identities.os.fsync", trace)
    d = create_and_plan(h)
    approve_current(h, d)
    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 10)
    blocker = sqlite3.connect(h.settings.database_path, isolation_level=None)

    class LockAfterApply(SimulatedProvisioner):
        def apply(self, *args: Any) -> ApplyResult:
            result = super().apply(*args)
            blocker.execute("BEGIN IMMEDIATE")
            return result

    worker = Worker(h.settings, h.db, LockAfterApply(h.settings.data_dir), clock=h.clock)
    worker.write_retry_delays = ()
    try:
        with pytest.raises((ServiceUnavailable, sqlite3.OperationalError)):
            worker.run_once()
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    evidence = h.settings.workdir_root / d["id"] / "identities.jsonl"
    assert evidence.is_file()
    for entry in (
        evidence,
        evidence.parent,
        h.settings.workdir_root,
        h.settings.workdir_root.parent,
    ):
        assert entry in synced, entry


def test_r5_4_plan_workdirs_are_created_durably(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[Path] = []
    real_fsync = os.fsync

    def trace(fd: int) -> None:
        synced.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        real_fsync(fd)

    monkeypatch.setattr("unitcompute.durable.os.fsync", trace)
    d = create_and_plan(harness)
    plan_dir = harness.settings.workdir_root / d["id"] / d["current_plan"]["plan_id"]
    assert plan_dir.parent in synced  # entry for the new plan directory
    assert harness.settings.workdir_root in synced  # entry for the deployment directory


# --------------------------------- R5-5: escaped delimiters in credential values


SUFFIX = "private-suffix-5ad4819f"


@pytest.mark.parametrize(
    "message",
    [
        json.dumps({"client_secret": f'ordinary-prefix"{SUFFIX}'}),
        f"password: 'it\\'s-{SUFFIX}'",
        f'api_key="unterminated {SUFFIX}\nnext line',
    ],
)
def test_r5_5_escaped_quotes_do_not_leak_at_any_boundary(harness: Harness, message: str) -> None:
    seen: list[str] = []

    def echo(messages: list[BaseMessage]) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, HumanMessage))
        return AIMessage(content=message)

    service = AgentService(
        harness.settings,
        harness.db,
        harness.container.deployments,
        lambda: ScriptedChatModel(script=[echo]),
    )
    reply = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "escaped-key-0001")
    )
    assert seen and all(SUFFIX not in s for s in seen)
    assert SUFFIX not in reply.reply
    with harness.db.read() as conn:
        stored = " ".join(r[0] for r in conn.execute("SELECT content FROM chat_messages"))
        response = conn.execute("SELECT response_json FROM agent_attempts").fetchone()[0]
    assert SUFFIX not in stored and SUFFIX not in response
    service._model_factory = None
    replay = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "escaped-key-0001")
    )
    assert SUFFIX not in replay.model_dump_json()


def test_r5_6_operator_guidance_does_not_mention_removed_command() -> None:
    root = Path(__file__).resolve().parents[1]
    for path in [
        *sorted((root / "src").rglob("*.py")),
        root / "docs" / "operations.md",
        root / "docs" / "api.md",
        root / "README.md",
    ]:
        text = path.read_text()
        assert "record-root-volume`;" not in text and "acknowledge-root-disk" not in text, path
    from unitcompute.worker import _missing_root_message

    assert "record-root-volume" not in _missing_root_message(["i-0123456789abcdef0"])
