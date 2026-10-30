"""Regressions for the first independent review round of 715e5e3.

Each test is adapted from a reviewer reproduction (security: test_review_adversarial.py;
reliability: test_independent_review.py) and asserts the corrected behaviour. Finding IDs
match docs/verification-ledger.md. Against 715e5e3 these tests fail; see the ledger.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import boto3
import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from moto import mock_aws
from pydantic import ValidationError

import iam_eval
from conftest import Harness, approve_current, auth, create_and_plan, launch, make_settings
from test_config_and_auth import AWS_TERRAFORM, JWT_SETTINGS, TERRAFORM_SETTINGS
from test_policy import AMI, INST, SG, SPEC, TARGETS, as_destroy, change, load, run
from unitcompute.agent.fake import ScriptedChatModel
from unitcompute.agent.service import AgentService
from unitcompute.auth import Principal
from unitcompute.config import Settings
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.errors import Conflict, RateLimited, ServiceUnavailable
from unitcompute.provisioning.aws import AwsEnvironment, TemporaryCredentials
from unitcompute.provisioning.base import OwnedResource, ProvisioningError, Readiness
from unitcompute.provisioning.policy import evaluate_plan
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.schemas import AgentMessageRequest, ApprovalRequest, DeploymentRequest
from unitcompute.services.deployments import DeploymentService
from unitcompute.worker import JobFailure, Worker

ALICE = Principal(subject="dev:alice", auth_method="dev")
ROOT = Path(__file__).resolve().parents[1]


def _attempts(h: Harness) -> list[str]:
    with h.db.read() as conn:
        return [r["status"] for r in conn.execute("SELECT status FROM agent_attempts")]


# ----------------------------------------------------------- S1: forgeable identities


@pytest.mark.parametrize(
    "auth_settings",
    [
        {"auth_mode": "dev"},
        {**JWT_SETTINGS, "auth_required_group": None},
    ],
)
def test_s1_real_provisioning_requires_verified_team_auth(
    tmp_path: Path, auth_settings: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError, match="provisioner=terraform requires auth_mode=jwt"):
        make_settings(tmp_path, **{**AWS_TERRAFORM, **auth_settings})


def test_s1_forged_dev_identity_cannot_queue_real_deployment(tmp_path: Path) -> None:
    """Reviewer reproduction: dev:mallory got 202 from a terraform-provisioner API."""
    with pytest.raises(ValidationError):
        Settings(data_dir=tmp_path / "data", auth_mode="dev", **AWS_TERRAFORM)
    settings = make_settings(tmp_path, **TERRAFORM_SETTINGS)
    Database(settings.database_path).migrate()
    from unitcompute.api.app import create_app

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth("mallory")
        )
    assert response.status_code == 401


# ------------------------------------------------- S2/R3: assistant reservations


def _slow_model(entered: list[int]) -> Any:
    class Slow(ScriptedChatModel):
        async def _agenerate(self, *args: Any, **kwargs: Any) -> ChatResult:
            entered.append(1)
            await asyncio.sleep(0.15)
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

    return Slow


def _service(h: Harness, factory: Any, **limits: Any) -> AgentService:
    settings = h.settings.model_copy(update=limits)
    return AgentService(settings, h.db, h.container.deployments, factory)


async def _gather(
    service: AgentService, requests: list[AgentMessageRequest], keys: list[str | None] | None = None
) -> list[Any]:
    keys = keys or [None] * len(requests)
    return await asyncio.gather(
        *[service.handle(ALICE, r, None, k) for r, k in zip(requests, keys, strict=True)],
        return_exceptions=True,
    )


def test_r3_concurrent_requests_cannot_exceed_daily_cap(harness: Harness) -> None:
    entered: list[int] = []
    Slow = _slow_model(entered)
    service = _service(harness, Slow, agent_max_messages_per_day=1)
    results = asyncio.run(_gather(service, [AgentMessageRequest(message="hi")] * 8))
    successes = [r for r in results if not isinstance(r, Exception)]
    assert len(successes) == 1
    assert all(isinstance(r, RateLimited) for r in results if isinstance(r, Exception))
    assert len(entered) == 1  # the provider was only called once


def test_r3_concurrent_requests_cannot_exceed_session_turns(harness: Harness) -> None:
    entered: list[int] = []
    Slow = _slow_model(entered)
    sid = "chat_" + "a" * 32
    now = database.to_db_time(database.utcnow())
    with harness.db.transaction() as conn:
        conn.execute("INSERT INTO chat_sessions VALUES (?, 'dev:alice', 0, ?, ?)", (sid, now, now))
    service = _service(harness, Slow, agent_max_session_turns=1)
    results = asyncio.run(_gather(service, [AgentMessageRequest(session_id=sid, message="hi")] * 6))
    assert sum(not isinstance(r, Exception) for r in results) == 1
    assert all(r.code == "session_turn_limit" for r in results if isinstance(r, Conflict))
    with harness.db.read() as conn:
        assert (
            conn.execute("SELECT turns FROM chat_sessions WHERE id = ?", (sid,)).fetchone()[0] == 1
        )


@pytest.mark.parametrize("failure", ["timeout", "provider_error"])
def test_r3_failed_attempts_stay_counted(harness: Harness, failure: str) -> None:
    entered: list[int] = []

    class Failing(ScriptedChatModel):
        async def _agenerate(self, *args: Any, **kwargs: Any) -> ChatResult:
            entered.append(1)
            if failure == "timeout":
                await asyncio.sleep(1)
            raise RuntimeError("offline provider failure")

    service = _service(harness, Failing, agent_max_messages_per_day=1, agent_timeout_seconds=0.05)

    async def attempts() -> list[Any]:
        out = []
        for _ in range(3):
            try:
                await service.handle(ALICE, AgentMessageRequest(message="hi"), None)
            except (ServiceUnavailable, RateLimited) as exc:
                out.append(exc.code)
        return out

    codes = asyncio.run(attempts())
    assert codes[0] in {"agent_timeout", "agent_unavailable"}
    assert codes[1:] == ["rate_limited", "rate_limited"]
    assert len(entered) == 1
    assert _attempts(harness) == ["failed"]


def test_r3_cancelled_attempt_stays_counted(harness: Harness) -> None:
    class Hang(ScriptedChatModel):
        async def _agenerate(self, *args: Any, **kwargs: Any) -> ChatResult:
            await asyncio.sleep(10)
            raise AssertionError("unreachable")

    service = _service(harness, Hang, agent_max_messages_per_day=1)

    async def cancel() -> None:
        task = asyncio.create_task(service.handle(ALICE, AgentMessageRequest(message="hi"), None))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    assert _attempts(harness) == ["failed"]
    with pytest.raises(RateLimited):
        asyncio.run(service.handle(ALICE, AgentMessageRequest(message="again"), None))


# ------------------------------------------------------ R6: chat idempotency


def test_r6_chat_idempotency_replays_without_second_model_call(harness: Harness) -> None:
    calls: list[int] = []

    def factory() -> ScriptedChatModel:
        calls.append(1)
        return ScriptedChatModel(script=[AIMessage(content="hello back")])

    harness.container.agent = AgentService(
        harness.settings, harness.db, harness.container.deployments, factory
    )
    headers = {**auth(), "Idempotency-Key": "review-chat-retry"}
    first = harness.client.post("/agent/messages", json={"message": "hello"}, headers=headers)
    second = harness.client.post("/agent/messages", json={"message": "hello"}, headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert _attempts(harness) == ["succeeded"]
    other = harness.client.post("/agent/messages", json={"message": "different"}, headers=headers)
    assert other.status_code == 409
    assert other.json()["error"]["code"] == "idempotency_key_reused"
    mallory = harness.client.post(
        "/agent/messages",
        json={"message": "hello"},
        headers={**auth("mallory"), "Idempotency-Key": "review-chat-retry"},
    )
    assert mallory.status_code == 200
    assert mallory.json()["session_id"] != first.json()["session_id"]


def test_r6_in_flight_duplicate_is_rejected(harness: Harness) -> None:
    entered: list[int] = []
    Slow = _slow_model(entered)
    service = _service(harness, Slow)
    request = AgentMessageRequest(message="hi")
    results = asyncio.run(_gather(service, [request, request], ["same-key-001", "same-key-001"]))
    errors = [r for r in results if isinstance(r, Exception)]
    assert len(errors) == 1
    assert isinstance(errors[0], Conflict)
    assert errors[0].code == "idempotency_in_progress"
    assert len(entered) == 1


def test_r6_failed_attempt_releases_key_but_counts(harness: Harness) -> None:
    class Failing(ScriptedChatModel):
        async def _agenerate(self, *args: Any, **kwargs: Any) -> ChatResult:
            raise RuntimeError("offline failure")

    service = _service(harness, Failing)
    for _ in range(2):
        with pytest.raises(ServiceUnavailable):
            asyncio.run(
                service.handle(ALICE, AgentMessageRequest(message="hi"), None, "retry-key-0001")
            )
    assert _attempts(harness) == ["failed", "failed"]


# ---------------------------------------------------- S3: execution binding


CHANGED = {
    "aws_account_id": "999999999999",
    "subnet_id": "subnet-fffffffffffffffff",
    "instance_profile_name": "replacement-profile",
    "state_bucket": "new-state-bucket",
}


@pytest.mark.parametrize("field", sorted(CHANGED))
def test_s3_changed_execution_config_invalidates_approval(harness: Harness, field: str) -> None:
    d = create_and_plan(harness)
    changed = harness.settings.model_copy(update={field: CHANGED[field]})
    service = DeploymentService(harness.db, changed, clock=harness.clock)
    p = d["current_plan"]
    with pytest.raises(Conflict) as exc:
        service.approve(
            ALICE,
            d["id"],
            ApprovalRequest(plan_id=p["plan_id"], plan_hash=p["plan_hash"]),
            None,
            None,
        )
    assert exc.value.code == "plan_stale"


@pytest.mark.parametrize("field", sorted(CHANGED))
def test_s3_worker_rechecks_execution_config(harness: Harness, field: str) -> None:
    d = create_and_plan(harness)
    approve_current(harness, d)
    changed = harness.settings.model_copy(update={field: CHANGED[field]})
    worker = Worker(changed, harness.db, harness.provisioner, clock=harness.clock)
    job = worker.claim()
    assert job is not None
    deployment, plan = worker._load(job)
    with pytest.raises(JobFailure) as exc:
        worker._precheck_apply(job, deployment, plan, harness.clock())
    assert exc.value.code == "plan_stale"


def test_s3_terraform_plan_bound_to_account_network_backend_and_roles(tmp_path: Path) -> None:
    """Reviewer reproduction with the real Terraform provisioner and a recording runner."""
    from test_runner_and_terraform import FakeAws, RecordingRunner
    from unitcompute.provisioning.policy import expected_tags
    from unitcompute.provisioning.runner import RunResult
    from unitcompute.provisioning.terraform import TFVARS_FILE, TerraformProvisioner

    class PolicyRunner(RecordingRunner):
        def run(self, args: Any, *, workdir: Path, **kwargs: Any) -> RunResult:
            if args[0] == "show":
                variables = json.loads((workdir / TFVARS_FILE).read_text())
                plan = load()
                plan["variables"] = {k: {"value": v} for k, v in variables.items()}
                spec = SPEC.__class__(
                    variables["deployment_id"],
                    variables["owner_tag"],
                    variables["name"],
                    variables["disk_gib"],
                    variables["region"],
                    variables["instance_type"],
                )
                tags = expected_tags(spec)
                inst = change(plan, INST)["change"]["after"]
                inst["tags"] = inst["tags_all"] = {**tags, "Name": "unitcompute-demo"}
                inst["volume_tags"] = {**tags, "Name": "unitcompute-demo-root"}
                group = change(plan, SG)["change"]["after"]
                group["tags"] = group["tags_all"] = {**tags, "Name": "unitcompute-demo"}
                return RunResult(0, json.dumps(plan), "")
            return super().run(args, workdir=workdir, **kwargs)

    settings = make_settings(tmp_path, **TERRAFORM_SETTINGS)
    db = Database(settings.database_path)
    db.migrate()
    service = DeploymentService(db, settings)
    principal = Principal(subject="user-1", auth_method="jwt")
    _, body = service.create_deployment(
        principal, DeploymentRequest(name="demo", disk_gib=8), None, None
    )
    worker = Worker(settings, db, TerraformProvisioner(settings, PolicyRunner(), FakeAws()))  # type: ignore[arg-type]
    assert worker.run_once()
    plan = service.get_deployment(principal, body["deployment_id"]).current_plan
    assert plan is not None and plan.status == "ready", plan
    for field, value in {
        "aws_account_id": "999999999999",
        "vpc_id": "vpc-fffffffffffffffff",
        "subnet_id": "subnet-fffffffffffffffff",
        "instance_profile_name": "replacement-profile",
        "state_bucket": "replacement-state",
        "plan_role_arn": "arn:aws:iam::123456789012:role/new-plan",
        "apply_role_arn": "arn:aws:iam::123456789012:role/new-apply",
    }.items():
        changed = Settings(**{**settings.model_dump(), field: value})
        with pytest.raises(Conflict) as exc:
            DeploymentService(db, changed).approve(
                principal,
                body["deployment_id"],
                ApprovalRequest(plan_id=plan.plan_id, plan_hash=plan.plan_hash or ""),
                None,
                None,
            )
        assert exc.value.code == "plan_stale", field
    # Unchanged configuration still approves.
    status, _ = service.approve(
        principal,
        body["deployment_id"],
        ApprovalRequest(plan_id=plan.plan_id, plan_hash=plan.plan_hash or ""),
        None,
        None,
    )
    assert status == 202


# ------------------------------------------------------------- S4: plan policy


def test_s4_provisioners_rejected() -> None:
    plan = load()
    resource = next(
        r for r in plan["configuration"]["root_module"]["resources"] if r["address"] == INST
    )
    resource["provisioners"] = [
        {"type": "local-exec", "expressions": {"command": {"constant_value": "id"}}}
    ]
    assert any("provisioners" in v for v in run(plan))


def test_s4_foreign_security_group_rejected() -> None:
    plan = load()
    change(plan, INST)["change"]["after"]["vpc_security_group_ids"] = ["sg-fffffffffffffffff"]
    assert any("dedicated security group" in v for v in run(plan))
    plan = load()
    resource = next(
        r for r in plan["configuration"]["root_module"]["resources"] if r["address"] == INST
    )
    resource["expressions"]["vpc_security_group_ids"] = {"constant_value": ["sg-fffffffffffffffff"]}
    assert any("dedicated security group" in v for v in run(plan))


def test_s4_existing_instance_must_use_its_own_group() -> None:
    plan = as_destroy(load())
    for c in plan["resource_changes"]:
        c["change"]["actions"] = ["no-op"]
        c["change"]["after"] = c["change"]["before"]
    inventory = [
        OwnedResource("instance", "i-0abc", "running"),
        OwnedResource("security_group", "sg-0abc", "exists"),
    ]
    assert run(plan, inventory=inventory) == []
    change(plan, INST)["change"]["after"]["vpc_security_group_ids"] = ["sg-0abc", "sg-0open"]
    assert any("dedicated security group" in v for v in run(plan, inventory=inventory))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda a: a.update(key_name="unexpected-ssh-key"),
        lambda a: a.update(tenancy="dedicated"),
        lambda a: a["root_block_device"][0].update(iops=80000, throughput=2000),
        lambda a: a.update(network_interface=[{"network_interface_id": "eni-1"}]),
        lambda a: a.update(source_dest_check=False),
    ],
)
def test_s4_unreviewed_instance_attributes_rejected(mutate: Any) -> None:
    plan = load()
    mutate(change(plan, INST)["change"]["after"])
    assert run(plan)


def test_s4_unreviewed_configuration_arguments_rejected() -> None:
    plan = load()
    resource = next(
        r for r in plan["configuration"]["root_module"]["resources"] if r["address"] == INST
    )
    resource["expressions"]["key_name"] = {"constant_value": "ssh"}
    assert any("unreviewed arguments" in v for v in run(plan))
    plan = load()
    resource = next(
        r for r in plan["configuration"]["root_module"]["resources"] if r["address"] == INST
    )
    resource["count_expression"] = {"constant_value": 5}
    assert any("meta-arguments" in v for v in run(plan))


@pytest.mark.terraform
def test_s4_real_plan_with_local_exec_and_foreign_group_rejected(tmp_path: Path) -> None:
    """Reviewer reproduction: a real pinned offline plan with both edits passed before."""
    from test_terraform_offline import TERRAFORM, _offline_plan
    from unitcompute.provisioning.base import template_dir

    if not Path(TERRAFORM).exists():
        pytest.skip("terraform binary not installed")
    source = tmp_path / "source"
    shutil.copytree(template_dir(), source)
    main = source / "main.tf"
    text = main.read_text().replace("[aws_security_group.vm.id]", '["sg-fffffffffffffffff"]')
    text = text.replace(
        'resource "aws_instance" "vm" {',
        'resource "aws_instance" "vm" {\n'
        '  provisioner "local-exec" {\n    command = "printf review-canary"\n  }',
    )
    main.write_text(text)
    plan = _offline_plan(TERRAFORM, source, tmp_path / "plan")
    result = evaluate_plan(
        plan, kind="create", spec=SPEC, targets=TARGETS, ami_id=AMI, inventory=[]
    )
    assert any("provisioners" in v for v in result.violations)
    assert any("dedicated security group" in v for v in result.violations)


# ------------------------------------------------------------------- S5: IAM


PLACEHOLDERS = {"state_bucket": "${state_bucket}"}
ALICE_SESSION = {"aws:PrincipalTag/UnitComputeDeployment": "dep_alice"}


def _allowed(policy: dict[str, Any], action: str, resource: str) -> bool:
    return iam_eval.allowed([policy], action, resource, ALICE_SESSION, PLACEHOLDERS)


STATE = "arn:aws:s3:::${state_bucket}/deployments/dep_alice/terraform.tfstate"
LOCK = STATE + ".tflock"


def test_s5_plan_role_reads_state_but_only_writes_lock_objects() -> None:
    policy = json.loads((ROOT / "docs/iam/plan-role-policy.json").read_text())
    assert _allowed(policy, "s3:GetObject", STATE)
    for action in ("s3:PutObject", "s3:DeleteObject"):
        assert not _allowed(policy, action, STATE), action
        assert _allowed(policy, action, LOCK), action
    assert not _allowed(
        policy, "s3:GetObject", "arn:aws:s3:::${state_bucket}/bootstrap/terraform.tfstate"
    )


def test_s5_apply_role_never_deletes_state() -> None:
    policy = json.loads((ROOT / "docs/iam/apply-role-policy.json").read_text())
    assert _allowed(policy, "s3:GetObject", STATE)
    assert _allowed(policy, "s3:PutObject", STATE)
    assert not _allowed(policy, "s3:DeleteObject", STATE)
    assert _allowed(policy, "s3:DeleteObject", LOCK)


# ---------------------------------------------------- R1: deletion verification


class _AwsBacked(SimulatedProvisioner):
    """Simulated Terraform, but inventory and ID lookups go to moto's EC2."""

    aws: AwsEnvironment
    creds = TemporaryCredentials("testing", "testing", "testing")

    def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
        return self.aws.owned_resources(deployment_id, self.creds)

    def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
        return self.aws.find_resources(resource_ids, self.creds)


def _delete_with(h: Harness, provisioner: SimulatedProvisioner, d: dict[str, Any]) -> Any:
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    worker = Worker(h.settings, h.db, provisioner, clock=h.clock)
    worker.run_once()
    pending = h.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    approve_current(h, pending)
    worker.run_once()
    return h.client.get(f"/deployments/{d['id']}", headers=auth()).json()


@mock_aws
def test_r1_untagged_vm_with_lost_state_blocks_deletion(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    d = launch(harness)
    ec2 = boto3.client("ec2", region_name="us-east-1")
    iid = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]
    with harness.db.transaction() as conn:
        conn.execute("UPDATE deployments SET instance_id = ? WHERE id = ?", (iid, d["id"]))
    harness.provisioner._state_path(d["id"]).unlink()  # state lost, tag never present
    provisioner = _AwsBacked(harness.settings.data_dir)
    provisioner.aws = AwsEnvironment(harness.settings)
    harness.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    Worker(harness.settings, harness.db, provisioner, clock=harness.clock).run_once()
    final = harness.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    state = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert state["State"]["Name"] == "running"
    # Round 2: the live, recorded VM is not in Terraform state, so the deletion preview
    # itself is rejected for operator reconciliation instead of reaching "deleted".
    assert final["status"] == "plan_failed"
    assert final["current_plan"]["status"] == "rejected"
    assert iid in final["current_plan"]["error"]["message"]
    assert (
        harness.client.post(
            "/deployments", json={"name": "next", "disk_gib": 8}, headers=auth()
        ).status_code
        == 409
    )


@mock_aws
def test_r1_retained_untagged_root_volume_blocks_deletion(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    d = launch(harness)
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, vid = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    path = harness.provisioner._state_path(d["id"])
    state = json.loads(path.read_text())
    state["aws_instance.vm"]["id"] = iid
    state["aws_instance.vm"]["root_block_device"][0]["volume_id"] = vid
    path.write_text(json.dumps(state))
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE deployments SET instance_id = ?, root_volume_id = ? WHERE id = ?",
            (iid, vid, d["id"]),
        )

    class RetainedVolume(_AwsBacked):
        def apply(self, *args: Any) -> Any:
            result = super().apply(*args)
            ec2.terminate_instances(InstanceIds=[iid])
            return result

    provisioner = RetainedVolume(harness.settings.data_dir)
    provisioner.aws = AwsEnvironment(harness.settings)
    final = _delete_with(harness, provisioner, d)
    assert ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"
    assert final["status"] == "recovery_required"
    assert vid in final["latest_job"]["error"]["message"]


def test_r1_unverifiable_deletion_keeps_recovery_and_quota(harness: Harness) -> None:
    class Unverifiable(SimulatedProvisioner):
        applied = False

        def apply(self, *args: Any) -> Any:
            self.applied = True
            return super().apply(*args)

        def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
            if self.applied:
                raise ProvisioningError("aws_unavailable", "Could not verify.")
            return super().find_resources(resource_ids)

    d = launch(harness)
    final = _delete_with(harness, Unverifiable(harness.settings.data_dir), d)
    assert final["status"] == "recovery_required"
    assert final["latest_job"]["error"]["code"] == "verification_failed"


def test_r1_lookup_failure_blocks_preview(harness: Harness) -> None:
    class Blind(SimulatedProvisioner):
        def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
            raise ProvisioningError("aws_unavailable", "Could not verify.")

    d = launch(harness)
    harness.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    Worker(
        harness.settings, harness.db, Blind(harness.settings.data_dir), clock=harness.clock
    ).run_once()
    after = harness.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    assert after["status"] == "plan_failed"
    assert after["current_plan"]["error"]["code"] == "aws_unavailable"


def test_r1_identities_recorded_at_creation(harness: Harness) -> None:
    d = launch(harness)
    resources = d["resources"]
    assert resources["instance_id"].startswith("i-")
    assert resources["security_group_id"].startswith("sg-")
    assert resources["root_volume_id"].startswith("vol-")


@mock_aws
def test_r1_find_resources_by_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    aws = AwsEnvironment(make_settings(tmp_path, **TERRAFORM_SETTINGS))
    creds = TemporaryCredentials("testing", "testing", "testing")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    running = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]
    gone = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]
    ec2.terminate_instances(InstanceIds=[gone])
    found = aws.find_resources(
        [running, gone, "i-0123456789abcdef0", "vol-0123456789abcdef0", "sg-0123456789abcdef0"],
        creds,
    )
    assert [r.resource_id for r in found] == [running]
    with pytest.raises(ProvisioningError):
        aws.find_resources(["eni-0123"], creds)


# --------------------------------------------- R2: contention cannot strand an apply


def _contended(h: Harness, hold_seconds: float | None) -> tuple[Worker, sqlite3.Connection]:
    blocker = sqlite3.connect(
        h.settings.database_path, isolation_level=None, timeout=10, check_same_thread=False
    )

    class Contended(SimulatedProvisioner):
        def apply(self, *args: Any) -> Any:
            result = super().apply(*args)
            blocker.execute("BEGIN IMMEDIATE")
            if hold_seconds is not None:
                threading.Timer(hold_seconds, lambda: blocker.execute("ROLLBACK")).start()
            return result

    worker = Worker(h.settings, h.db, Contended(h.settings.data_dir), clock=h.clock)
    worker.write_retry_delays = (0.05, 0.05, 0.1)
    return worker, blocker


def test_r2_transient_contention_is_retried(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = create_and_plan(harness)
    accepted = approve_current(harness, d)
    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 30)
    worker, blocker = _contended(harness, hold_seconds=0.1)
    try:
        assert worker.run_once()
    finally:
        time.sleep(0.2)
        blocker.close()
    job = harness.client.get(f"/jobs/{accepted['job_id']}", headers=auth()).json()
    assert job["status"] == "succeeded"
    detail = harness.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    assert detail["status"] == "active"


def test_r2_persistent_contention_recovers_without_replay(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reviewer reproduction: job/deployment stayed running/applying behind a live worker."""
    d = create_and_plan(harness)
    accepted = approve_current(harness, d)
    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 30)
    worker, blocker = _contended(harness, hold_seconds=None)
    applies: list[int] = []
    original = worker.provisioner.apply

    def counting(*args: Any) -> Any:
        applies.append(1)
        return original(*args)

    worker.provisioner.apply = counting  # type: ignore[method-assign]
    try:
        with pytest.raises(ServiceUnavailable):
            worker.run_once()
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert worker.run_once() is False  # recovered the stranded job; nothing else to do
    job = harness.client.get(f"/jobs/{accepted['job_id']}", headers=auth()).json()
    detail = harness.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    assert job["status"] == "recovery_required"
    assert detail["status"] == "recovery_required"
    assert applies == [1]  # never replayed


# --------------------------------------------------------------- R4: readiness


def _ready(h: Harness) -> Any:
    return h.client.get("/readyz")


def test_r4_not_ready_without_worker(harness: Harness) -> None:
    response = _ready(harness)
    assert response.status_code == 503
    assert response.json()["ready"] is False


def test_r4_not_ready_with_stale_or_unhealthy_worker(harness: Harness) -> None:
    worker = Worker(harness.settings, harness.db, harness.provisioner)
    assert worker.self_check()
    assert _ready(harness).status_code == 200
    with harness.db.transaction() as conn:
        conn.execute("UPDATE worker_heartbeats SET heartbeat_at = '2000-01-01T00:00:00+00:00'")
    assert _ready(harness).status_code == 503

    class Broken(SimulatedProvisioner):
        def self_check(self) -> dict[str, Any]:
            raise ProvisioningError("aws_identity_mismatch", "wrong role")

    broken = Worker(harness.settings, harness.db, Broken(harness.settings.data_dir))
    assert broken.self_check() is False
    body = _ready(harness).json()
    assert body["ready"] is False
    assert body["checks"]["worker_self_check"]["code"] == "aws_identity_mismatch"


def test_r4_unhealthy_worker_takes_no_jobs(harness: Harness) -> None:
    class Broken(SimulatedProvisioner):
        def self_check(self) -> dict[str, Any]:
            raise ProvisioningError("terraform_version_mismatch", "wrong terraform")

    harness.client.post("/deployments", json={"name": "demo", "disk_gib": 8}, headers=auth())
    worker = Worker(harness.settings, harness.db, Broken(harness.settings.data_dir))
    assert worker.run_once() is False
    with harness.db.read() as conn:
        assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "queued"


def test_r4_disabled_provisioning_does_not_need_worker(tmp_path: Path) -> None:
    from unitcompute.api.app import create_app

    settings = make_settings(tmp_path, provisioner="disabled")
    Database(settings.database_path).migrate()
    with TestClient(create_app(settings)) as client:
        assert client.get("/readyz").status_code == 200


def test_r4_terraform_self_check_verifies_role_identities(tmp_path: Path) -> None:
    from test_runner_and_terraform import FakeAws, RecordingRunner
    from unitcompute.provisioning.terraform import TerraformProvisioner

    settings = make_settings(tmp_path, **TERRAFORM_SETTINGS)
    good = TerraformProvisioner(settings, RecordingRunner(), FakeAws())  # type: ignore[arg-type]
    checks = good.self_check()
    assert checks["terraform_version"] == "1.17.1"
    assert checks["plan_role"]["role"] != checks["apply_role"]["role"]

    class SameRole(FakeAws):
        def verify_role_identity(self, role: str) -> dict[str, str]:
            return {"account": "****9012", "role": "shared"}

    with pytest.raises(ProvisioningError):
        TerraformProvisioner(settings, RecordingRunner(), SameRole()).self_check()  # type: ignore[arg-type]


class _FakeClient:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses

    def __getattr__(self, name: str) -> Any:
        def call(**kwargs: Any) -> Any:
            value = self.responses[name]
            if isinstance(value, Exception):
                raise value
            return value(**kwargs) if callable(value) else value

        return call


class _FakeSession:
    def __init__(self, clients: dict[str, _FakeClient], **kwargs: Any) -> None:
        self.clients = clients

    def client(self, service: str, config: Any = None) -> _FakeClient:
        return self.clients[service]


def _aws_with(tmp_path: Path, **clients: _FakeClient) -> AwsEnvironment:
    settings = make_settings(tmp_path, **TERRAFORM_SETTINGS)
    return AwsEnvironment(settings, session_factory=lambda **kw: _FakeSession(clients))


@pytest.mark.parametrize(
    ("arn", "account", "ok"),
    [
        (
            "arn:aws:sts::123456789012:assumed-role/unitcompute-plan/uc-selfcheck-plan",
            "123456789012",
            True,
        ),
        ("arn:aws:sts::123456789012:assumed-role/someone-else/uc", "123456789012", False),
        ("arn:aws:sts::999999999999:assumed-role/unitcompute-plan/uc", "999999999999", False),
        ("arn:aws:iam::123456789012:user/admin", "123456789012", False),
    ],
)
def test_r4_role_identity_verification(tmp_path: Path, arn: str, account: str, ok: bool) -> None:
    creds = {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}
    sts = _FakeClient(
        {"assume_role": creds, "get_caller_identity": {"Account": account, "Arn": arn}}
    )
    aws = _aws_with(tmp_path, sts=sts)
    if ok:
        assert aws.verify_role_identity("plan") == {
            "account": "****9012",
            "role": "unitcompute-plan",
        }
    else:
        with pytest.raises(ProvisioningError):
            aws.verify_role_identity("plan")


# -------------------------------------------------------- R5: connection readiness


def _status(state: str, instance: str, system: str) -> dict[str, Any]:
    return {
        "InstanceStatuses": [
            {
                "InstanceState": {"Name": state},
                "InstanceStatus": {"Status": instance},
                "SystemStatus": {"Status": system},
            }
        ]
    }


@pytest.mark.parametrize(
    ("ec2", "ssm", "expected"),
    [
        (
            _status("running", "ok", "ok"),
            [{"InstanceId": "i-1", "PingStatus": "Online", "ResourceType": "EC2Instance"}],
            Readiness("ok", "Online"),
        ),
        (_status("running", "initializing", "ok"), [], Readiness("initializing", "NotRegistered")),
        (
            _status("running", "impaired", "ok"),
            [{"InstanceId": "i-1", "PingStatus": "ConnectionLost"}],
            Readiness("impaired", "ConnectionLost"),
        ),
        (
            _status("running", "ok", "ok"),
            [{"InstanceId": "i-other", "PingStatus": "Online", "ResourceType": "EC2Instance"}],
            Readiness("ok", "NotRegistered"),
        ),
        (
            _status("running", "ok", "ok"),
            [{"InstanceId": "i-1", "PingStatus": "Online", "ResourceType": "ManagedInstance"}],
            Readiness("ok", "NotRegistered"),
        ),
        (
            _status("stopped", "not-applicable", "not-applicable"),
            [],
            Readiness("stopped", "NotRegistered"),
        ),
    ],
)
def test_r5_connection_readiness_reads_ec2_checks_and_exact_ssm_identity(
    tmp_path: Path, ec2: dict[str, Any], ssm: list[dict[str, Any]], expected: Readiness
) -> None:
    aws = _aws_with(
        tmp_path,
        ec2=_FakeClient({"describe_instance_status": ec2}),
        ssm=_FakeClient({"describe_instance_information": {"InstanceInformationList": ssm}}),
    )
    readiness = aws.connection_readiness("i-1", TemporaryCredentials("a", "b", "c"))
    assert readiness == expected
    assert readiness.ready is (expected == Readiness("ok", "Online"))


def test_r5_infrastructure_success_is_distinct_from_connection_readiness(
    harness: Harness,
) -> None:
    status = {"ssm": "NotRegistered"}

    class Registering(SimulatedProvisioner):
        def connection_readiness(self, instance_id: str) -> Readiness:
            return Readiness("ok", status["ssm"])

    settings = harness.settings.model_copy(
        update={"readiness_timeout_seconds": 0, "readiness_refresh_seconds": 60}
    )
    d = create_and_plan(harness)
    approve_current(harness, d)
    worker = Worker(settings, harness.db, Registering(settings.data_dir), clock=harness.clock)
    assert worker.run_once()
    detail = harness.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    assert detail["status"] == "active"
    assert detail["latest_job"]["status"] == "succeeded"
    assert detail["access"]["ready"] is False
    assert detail["resources"]["connection"]["ssm_ping_status"] == "NotRegistered"
    assert any("Not ready yet" in r for r in detail["access"]["requirements"])

    status["ssm"] = "Online"
    harness.clock.advance(seconds=61)
    worker.housekeeping()
    later = harness.client.get(f"/deployments/{d['id']}", headers=auth()).json()
    assert later["access"]["ready"] is True
    assert later["resources"]["connection"]["ssm_ping_status"] == "Online"


def test_r5_readiness_wait_is_bounded(harness: Harness) -> None:
    calls: list[int] = []

    class NeverReady(SimulatedProvisioner):
        def connection_readiness(self, instance_id: str) -> Readiness:
            calls.append(1)
            return Readiness("initializing", "NotRegistered")

    settings = harness.settings.model_copy(
        update={"readiness_timeout_seconds": 0.3, "readiness_poll_seconds": 0.1}
    )
    d = create_and_plan(harness)
    approve_current(harness, d)
    started = time.monotonic()
    Worker(settings, harness.db, NeverReady(settings.data_dir), clock=harness.clock).run_once()
    assert time.monotonic() - started < 3
    assert 2 <= len(calls) <= 6


# ------------------------------------------------------------- pricing provenance


def test_price_snapshot_is_labelled_unverified(harness: Harness) -> None:
    d = create_and_plan(harness)
    cost = d["current_plan"]["cost"]
    snapshot = cost["price_snapshot"]
    assert snapshot["verified_against_aws_on"] is None
    assert "illustrative" in snapshot["basis"]
    assert "recorded_on" not in snapshot
    assert snapshot["live_quote"] is False
    assert "not a quote" in cost["disclaimer"]
