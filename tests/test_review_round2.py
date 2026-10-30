"""Regressions for the second independent review round of 910e9c0.

Adapted from security2 ``test_security2_independent.py`` and reliability2
``test_reliability_review2.py``. IDs match docs/verification-ledger.md.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import boto3
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage
from moto import mock_aws

import iam_eval
from conftest import (
    FakeClock,
    Harness,
    approve_current,
    auth,
    create_and_plan,
    launch,
    make_settings,
)
from test_config_and_auth import JWT_SETTINGS, TERRAFORM_SETTINGS
from unitcompute.agent.fake import ScriptedChatModel
from unitcompute.agent.service import AgentService
from unitcompute.auth import JwtAuthenticator, Principal
from unitcompute.db import database
from unitcompute.db.database import Database, to_db_time
from unitcompute.errors import Conflict, ServiceUnavailable, Unauthenticated
from unitcompute.identities import IdentityLedger
from unitcompute.provisioning.aws import (
    AwsEnvironment,
    TemporaryCredentials,
    packed_session_policy,
    session_policy,
)
from unitcompute.provisioning.base import (
    ApplyResult,
    OwnedResource,
    ProvisioningError,
    Readiness,
)
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.schemas import AgentMessageRequest
from unitcompute.services.deployments import DeploymentService
from unitcompute.worker import Worker

ROOT = Path(__file__).resolve().parents[1]
CREDS = TemporaryCredentials("testing", "testing", "testing")
ALICE = Principal(subject="dev:alice", auth_method="dev")


def _detail(h: Harness, dep: str) -> dict[str, Any]:
    body: dict[str, Any] = h.client.get(f"/deployments/{dep}", headers=auth()).json()
    return body


class _AwsBacked(SimulatedProvisioner):
    """Simulated Terraform; every AWS read goes to moto through the real AwsEnvironment."""

    def __init__(self, h: Any) -> None:
        super().__init__(h.settings.data_dir)
        self.aws = AwsEnvironment(h.settings)

    def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
        return self.aws.owned_resources(deployment_id, CREDS)

    def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
        return self.aws.find_resources(resource_ids, CREDS)

    def instance_volumes(self, instance_ids: list[str]) -> dict[str, list[str]]:
        return self.aws.instance_volumes(instance_ids, CREDS)


def _replan(h: Any, provisioner: SimulatedProvisioner, dep: str, route: str) -> Any:
    assert h.client.post(f"/deployments/{dep}/{route}", headers=auth()).status_code == 202
    worker = Worker(h.settings, h.db, provisioner, clock=h.clock)
    assert worker.run_once()
    return worker, _detail(h, dep)


@pytest.fixture
def moto_env(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        yield boto3.client("ec2", region_name="us-east-1")


# --------------------------------------------------- S2-1: JWKS key removal


def test_s2_1_removed_signing_key_stops_working(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(key: Any, kid: str) -> dict[str, Any]:
        data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        return {**data, "kid": kid, "use": "sig", "alg": "RS256"}

    published: dict[str, Any] = {"keys": [jwk(old, "old")]}
    clients: list[Any] = []
    original_init = jwt.PyJWKClient.__init__

    def init(client: Any, *args: Any, **kwargs: Any) -> None:
        original_init(client, *args, **kwargs)
        clients.append(client)

    def fetch(client: Any) -> dict[str, Any]:
        client.jwk_set_cache.put(published)
        return published

    monkeypatch.setattr(jwt.PyJWKClient, "__init__", init)
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch)
    authenticator = JwtAuthenticator(make_settings(tmp_path, **JWT_SETTINGS))

    def token(key: Any, kid: str, sub: str) -> str:
        now = int(time.time())
        claims = {
            "iss": JWT_SETTINGS["auth_issuer"],
            "aud": JWT_SETTINGS["auth_audience"],
            "sub": sub,
            "iat": now,
            "exp": now + 600,
            "groups": ["unitcompute-team"],
        }
        return f"Bearer {jwt.encode(claims, key, algorithm='RS256', headers={'kid': kid})}"

    assert authenticator.authenticate(token(old, "old", "alice")).subject == "alice"
    published = {"keys": [jwk(new, "new")]}
    clients[0].jwk_set_cache.put(None)  # the bounded JWKS cache expired
    with pytest.raises(Unauthenticated):
        authenticator.authenticate(token(old, "old", "victim"))
    assert authenticator.authenticate(token(new, "new", "bob")).subject == "bob"


def test_s2_1_jwks_cache_lifespan_is_bounded_and_configurable(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, **JWT_SETTINGS, auth_jwks_cache_seconds=60)
    client = JwtAuthenticator(settings)._resolve_key.__closure__[0].cell_contents  # type: ignore[attr-defined]
    assert client.jwk_set_cache.lifespan == 60


# ------------------------------------------------ S2-2: scoped session credentials


ALICE_DEP = "dep_" + "a" * 32
BOB_DEP = "dep_" + "b" * 32


def _settings(tmp_path: Path) -> Any:
    return make_settings(tmp_path, **TERRAFORM_SETTINGS)


def _placeholders(settings: Any) -> dict[str, str]:
    return {
        "state_bucket": settings.state_bucket,
        "account_id": settings.aws_account_id,
        "subnet_id": settings.subnet_id,
        "vpc_id": settings.vpc_id,
        "ssm_instance_role_arn": f"arn:aws:iam::{settings.aws_account_id}:role/unitcompute-ssm",
    }


def _role(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((ROOT / "docs/iam" / name).read_text())
    return data


def _context(session_dep: str | None, **extra: str) -> dict[str, str]:
    base = {"aws:RequestedRegion": "us-east-1"}
    if session_dep:
        base["aws:PrincipalTag/UnitComputeDeployment"] = session_dep
    return {**base, **extra}


def test_s2_2_assume_role_passes_scoped_policy_and_tag(tmp_path: Path) -> None:
    recorded: list[dict[str, Any]] = []

    class Sts:
        def assume_role(self, **kwargs: Any) -> Any:
            recorded.append(kwargs)
            return {
                "Credentials": {"AccessKeyId": "o", "SecretAccessKey": "o", "SessionToken": "o"}
            }

    class Session:
        def client(self, *args: Any, **kwargs: Any) -> Sts:
            return Sts()

    aws = AwsEnvironment(_settings(tmp_path), session_factory=lambda **kw: Session())
    aws.credentials("apply", "uc-apply-alice", ALICE_DEP)
    aws.credentials("plan", "uc-inventory")
    scoped, unscoped = recorded
    assert scoped["Tags"] == [{"Key": "UnitComputeDeployment", "Value": ALICE_DEP}]
    assert len(scoped["Policy"]) <= 2048
    assert ALICE_DEP in scoped["Policy"]
    assert "Tags" not in unscoped
    assert "s3:" not in unscoped["Policy"]  # no state access without a deployment


@pytest.mark.parametrize(
    ("action", "resource_kind", "context_extra", "allowed_for_alice", "allowed_for_bob"),
    [
        (
            "ec2:TerminateInstances",
            "instance",
            {"ec2:ResourceTag/ManagedBy": "unitcompute"},
            True,
            False,
        ),
        (
            "ec2:ModifyInstanceMetadataOptions",
            "instance",
            {"ec2:ResourceTag/ManagedBy": "unitcompute"},
            True,
            False,
        ),
        (
            "ec2:DeleteSecurityGroup",
            "security-group",
            {"ec2:ResourceTag/ManagedBy": "unitcompute"},
            True,
            False,
        ),
        ("s3:PutObject", "state", {}, True, False),
        ("s3:GetObject", "state", {}, True, False),
        ("s3:DeleteObject", "state", {}, False, False),
        ("s3:DeleteObject", "lock", {}, True, False),
    ],
)
def test_s2_2_apply_session_cannot_cross_deployments(
    tmp_path: Path,
    action: str,
    resource_kind: str,
    context_extra: dict[str, str],
    allowed_for_alice: bool,
    allowed_for_bob: bool,
) -> None:
    settings = _settings(tmp_path)
    placeholders = _placeholders(settings)
    session = session_policy(settings, "apply", ALICE_DEP)
    role = _role("apply-role-policy.json")

    def resource(dep: str) -> str:
        account = settings.aws_account_id
        state = f"arn:aws:s3:::{settings.state_bucket}/deployments/{dep}/terraform.tfstate"
        return {
            "instance": f"arn:aws:ec2:us-east-1:{account}:instance/i-0123456789abcdef0",
            "security-group": f"arn:aws:ec2:us-east-1:{account}:security-group/sg-012345678",
            "state": state,
            "lock": f"{state}.tflock",
        }[resource_kind]

    def check(dep: str) -> bool:
        context = _context(ALICE_DEP, **context_extra)
        if resource_kind in {"instance", "security-group"}:
            context["ec2:ResourceTag/UnitComputeDeployment"] = dep
        return iam_eval.allowed([role, session], action, resource(dep), context, placeholders)

    assert check(ALICE_DEP) is allowed_for_alice
    assert check(BOB_DEP) is allowed_for_bob


def test_s2_2_session_policy_alone_enforces_scope(tmp_path: Path) -> None:
    """The session policy scopes the session even if a role policy were broader."""
    settings = _settings(tmp_path)
    session = session_policy(settings, "apply", ALICE_DEP)
    account = settings.aws_account_id
    instance = f"arn:aws:ec2:us-east-1:{account}:instance/i-0123456789abcdef0"
    for dep, expected in ((ALICE_DEP, "allow"), (BOB_DEP, "implicit")):
        context = {
            "ec2:ResourceTag/ManagedBy": "unitcompute",
            "ec2:ResourceTag/UnitComputeDeployment": dep,
        }
        for action in ("ec2:TerminateInstances", "ec2:ModifyInstanceMetadataOptions"):
            assert iam_eval.decision(session, action, instance, context, {}) == expected
    bob_state = f"arn:aws:s3:::{settings.state_bucket}/deployments/{BOB_DEP}/terraform.tfstate"
    assert iam_eval.decision(session, "s3:PutObject", bob_state, {}, {}) == "implicit"


def test_s2_2_role_policy_alone_enforces_scope(tmp_path: Path) -> None:
    """Defence in depth: even without a session policy, the role requires matching tags."""
    settings = _settings(tmp_path)
    role = _role("apply-role-policy.json")
    account = settings.aws_account_id
    instance = f"arn:aws:ec2:us-east-1:{account}:instance/i-0123456789abcdef0"
    for dep, expected in ((ALICE_DEP, True), (BOB_DEP, False)):
        context = _context(
            ALICE_DEP,
            **{
                "ec2:ResourceTag/ManagedBy": "unitcompute",
                "ec2:ResourceTag/UnitComputeDeployment": dep,
            },
        )
        assert (
            iam_eval.allowed(
                [role], "ec2:TerminateInstances", instance, context, _placeholders(settings)
            )
            is expected
        )
    # An untagged session matches nothing that depends on the principal tag.
    context = _context(
        None,
        **{
            "ec2:ResourceTag/ManagedBy": "unitcompute",
            "ec2:ResourceTag/UnitComputeDeployment": ALICE_DEP,
        },
    )
    assert not iam_eval.allowed(
        [role], "ec2:TerminateInstances", instance, context, _placeholders(settings)
    )


def test_s2_2_launch_requires_this_deployments_tag(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    session = session_policy(settings, "apply", ALICE_DEP)
    role = _role("apply-role-policy.json")
    instance = f"arn:aws:ec2:us-east-1:{settings.aws_account_id}:instance/*"
    for tag, expected in ((ALICE_DEP, True), (BOB_DEP, False)):
        context = _context(
            ALICE_DEP,
            **{
                "aws:RequestTag/ManagedBy": "unitcompute",
                "aws:RequestTag/UnitComputeDeployment": tag,
                "ec2:InstanceType": "t3.micro",
                "ec2:MetadataHttpTokens": "required",
            },
        )
        assert (
            iam_eval.allowed(
                [role, session], "ec2:RunInstances", instance, context, _placeholders(settings)
            )
            is expected
        )


def test_s2_2_plan_session_is_read_only_for_its_own_state(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    session = session_policy(settings, "plan", ALICE_DEP)
    role = _role("plan-role-policy.json")
    placeholders = _placeholders(settings)

    def state(dep: str) -> str:
        return f"arn:aws:s3:::{settings.state_bucket}/deployments/{dep}/terraform.tfstate"

    ctx = _context(ALICE_DEP)
    assert iam_eval.allowed([role, session], "s3:GetObject", state(ALICE_DEP), ctx, placeholders)
    assert not iam_eval.allowed([role, session], "s3:GetObject", state(BOB_DEP), ctx, placeholders)
    assert not iam_eval.allowed(
        [role, session], "s3:PutObject", state(ALICE_DEP), ctx, placeholders
    )
    assert iam_eval.allowed(
        [role, session], "s3:PutObject", state(ALICE_DEP) + ".tflock", ctx, placeholders
    )


def test_s2_2_unscoped_sessions(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    apply_identity_only = session_policy(settings, "apply", None)
    instance = f"arn:aws:ec2:us-east-1:{settings.aws_account_id}:instance/i-0123456789abcdef0"
    assert iam_eval.decision(apply_identity_only, "ec2:TerminateInstances", instance, {}, {}) == (
        "deny"
    )
    plan_read_only = session_policy(settings, "plan", None)
    assert iam_eval.decision(plan_read_only, "ec2:DescribeInstances", "*", {}, {}) == "allow"
    state = f"arn:aws:s3:::{settings.state_bucket}/deployments/{ALICE_DEP}/terraform.tfstate"
    assert iam_eval.decision(plan_read_only, "s3:GetObject", state, {}, {}) == "implicit"


def test_s2_2_oversized_session_policy_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr("unitcompute.provisioning.aws.MAX_SESSION_POLICY_CHARS", 500)
    with pytest.raises(ProvisioningError) as exc:
        packed_session_policy(settings, "apply", ALICE_DEP)
    assert exc.value.code == "session_policy_too_large"
    from test_runner_and_terraform import FakeAws, RecordingRunner
    from unitcompute.provisioning.terraform import TerraformProvisioner

    provisioner = TerraformProvisioner(settings, RecordingRunner(), FakeAws())  # type: ignore[arg-type]
    with pytest.raises(ProvisioningError):
        provisioner.self_check()


def test_s2_2_terraform_provisioner_scopes_plan_and_apply(tmp_path: Path) -> None:
    from test_runner_and_terraform import FakeAws, RecordingRunner
    from unitcompute.provisioning.base import DeploymentSpec
    from unitcompute.provisioning.terraform import TerraformProvisioner

    aws = FakeAws()
    provisioner = TerraformProvisioner(_settings(tmp_path), RecordingRunner(), aws)  # type: ignore[arg-type]
    spec = DeploymentSpec(ALICE_DEP, "0123456789abcdef", "demo", 8, "us-east-1", "t3.micro")
    workdir = tmp_path / "data" / "work" / ALICE_DEP / "plan_x"
    provisioner.plan(spec, "create", workdir, None)
    provisioner.apply(spec, workdir, workdir / "tfplan")
    assert list(zip(aws.roles, aws.scopes, strict=True)) == [
        ("plan", ALICE_DEP),
        ("apply", ALICE_DEP),
    ]


# ------------------------------------------- S2-3 / R2-6: replay without provider


def test_s2_3_completed_replay_does_not_need_provider(harness: Harness) -> None:
    request = AgentMessageRequest(message="hi")
    good = AgentService(
        harness.settings,
        harness.db,
        harness.container.deployments,
        lambda: ScriptedChatModel(script=[AIMessage(content="hello")]),
    )
    first = asyncio.run(good.handle(ALICE, request, None, "completed-key"))
    calls: list[int] = []

    def unavailable() -> Any:
        calls.append(1)
        raise ServiceUnavailable("provider unavailable", code="agent_unavailable")

    for factory in (unavailable, None):
        restarted = AgentService(
            harness.settings, harness.db, harness.container.deployments, factory
        )
        assert asyncio.run(restarted.handle(ALICE, request, None, "completed-key")) == first
        with pytest.raises(Conflict) as exc:
            asyncio.run(
                restarted.handle(ALICE, AgentMessageRequest(message="other"), None, "completed-key")
            )
        assert exc.value.code == "idempotency_key_reused"
    assert calls == []


def test_s2_3_completed_replay_over_http_with_provider_down(harness: Harness) -> None:
    harness.container.agent = AgentService(
        harness.settings,
        harness.db,
        harness.container.deployments,
        lambda: ScriptedChatModel(script=[AIMessage(content="hello")]),
    )
    headers = {**auth(), "Idempotency-Key": "http-replay-0001"}
    first = harness.client.post("/agent/messages", json={"message": "hi"}, headers=headers)
    harness.container.agent = AgentService(
        harness.settings, harness.db, harness.container.deployments, None
    )
    second = harness.client.post("/agent/messages", json={"message": "hi"}, headers=headers)
    assert second.status_code == 200
    assert second.json() == first.json()


# ------------------------------------------------ R2-4: stranded chat reservation


def _strand_reservation(h: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reviewer reproduction: cancellation while the database is locked."""
    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 20)
    monkeypatch.setattr("unitcompute.agent.service.MARK_FAILED_RETRY_DELAYS", (0.01,))
    blocker = sqlite3.connect(h.settings.database_path, isolation_level=None)

    class Interrupted(AgentService):
        async def _run(self, *args: Any) -> Any:
            blocker.execute("BEGIN IMMEDIATE")
            raise asyncio.CancelledError

    service = Interrupted(h.settings, h.db, h.container.deployments, ScriptedChatModel)
    try:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(
                service.handle(ALICE, AgentMessageRequest(message="hi"), None, "cancelled-key")
            )
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()


def test_r2_4_stranded_reservation_expires_after_its_lease(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strand_reservation(harness, monkeypatch)
    with harness.db.read() as conn:
        assert conn.execute("SELECT status FROM agent_attempts").fetchone()[0] == "reserved"
    restarted = AgentService(
        harness.settings,
        harness.db,
        harness.container.deployments,
        lambda: ScriptedChatModel(script=[AIMessage(content="ok")]),
    )
    request = AgentMessageRequest(message="hi")
    # Within the lease the key is still in progress (no concurrent replay).
    with pytest.raises(Conflict) as exc:
        asyncio.run(restarted.handle(ALICE, request, None, "cancelled-key"))
    assert exc.value.code == "idempotency_in_progress"
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE agent_attempts SET created_at = '2020-01-01T00:00:00+00:00', "
            "lease_expires_at = '2020-01-01T00:01:45+00:00'"
        )
    reply = asyncio.run(restarted.handle(ALICE, request, None, "cancelled-key"))
    assert reply.reply
    with harness.db.read() as conn:
        statuses = [r[0] for r in conn.execute("SELECT status FROM agent_attempts ORDER BY id")]
    assert statuses == ["failed", "succeeded"]  # the stranded attempt stays counted


def test_r2_4_failure_marking_retries_through_contention(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 20)
    blocker = sqlite3.connect(
        harness.settings.database_path, isolation_level=None, check_same_thread=False
    )

    class Interrupted(AgentService):
        async def _run(self, *args: Any) -> Any:
            blocker.execute("BEGIN IMMEDIATE")
            threading.Timer(0.1, lambda: blocker.execute("ROLLBACK")).start()
            raise asyncio.CancelledError

    service = Interrupted(
        harness.settings, harness.db, harness.container.deployments, ScriptedChatModel
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(service.handle(ALICE, AgentMessageRequest(message="hi"), None, "key-12345"))
    time.sleep(0.2)
    blocker.close()
    with harness.db.read() as conn:
        row = conn.execute("SELECT status, idempotency_key FROM agent_attempts").fetchone()
    assert (row[0], row[1]) == ("failed", None)


# --------------------------------- R2-1: a recorded live VM blocks repair creation


def test_r2_1_known_live_vm_blocks_second_vm(harness: Harness, moto_env: Any) -> None:
    ec2 = moto_env
    h = harness
    d = launch(h)
    old = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]
    with h.db.transaction() as conn:
        conn.execute("UPDATE deployments SET instance_id = ? WHERE id = ?", (old, d["id"]))
    h.provisioner._state_path(d["id"]).unlink()  # state lost; the VM has no tag
    launched: list[str] = []

    class CreateSecond(_AwsBacked):
        def apply(self, spec: Any, workdir: Any, plan_path: Any) -> ApplyResult:
            launched.append(spec.deployment_id)
            return ApplyResult()

    _, pending = _replan(h, CreateSecond(h), d["id"], "plan")
    assert pending["status"] == "plan_failed"
    assert pending["current_plan"]["status"] == "rejected"
    assert old in pending["current_plan"]["error"]["message"]
    assert launched == []
    running = [
        i
        for r in ec2.describe_instances()["Reservations"]
        for i in r["Instances"]
        if i["State"]["Name"] == "running"
    ]
    assert len(running) == 1


def test_r2_1_identity_history_survives_replacement(harness: Harness) -> None:
    d = launch(harness)
    first_instance = d["resources"]["instance_id"]
    with harness.db.transaction() as conn:
        conn.execute(
            "UPDATE deployments SET instance_id = 'i-0fffffffffffffff0' WHERE id = ?", (d["id"],)
        )
    with harness.db.transaction() as conn:
        known = IdentityLedger(harness.settings.workdir_root)
        known.import_evidence(conn, d["id"])
        ids = known.known(conn, d["id"]).instances
    assert {first_instance, "i-0fffffffffffffff0"} <= ids


def test_r2_1_identity_rows_are_append_only(harness: Harness) -> None:
    d = launch(harness)
    with harness.db.transaction() as conn:
        conn.execute(
            "INSERT INTO identity_acknowledgements (deployment_id, instance_id, operator, "
            "reason, recorded_at) VALUES (?, 'i-0123456789', 'ops', 'test', 'now')",
            (d["id"],),
        )
    for statement in (
        "UPDATE deployment_resources SET resource_id = 'i-00000000'",
        "DELETE FROM deployment_resources",
        "UPDATE identity_acknowledgements SET reason = 'changed'",
        "DELETE FROM identity_acknowledgements",
    ):
        conn = harness.db.connect()
        try:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(statement)
        finally:
            conn.close()


# ------------------------------ R2-2: returned IDs survive verification failures


def test_r2_2_apply_outputs_persist_when_inventory_fails(harness: Harness, moto_env: Any) -> None:
    ec2 = moto_env
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    iid = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0][
        "InstanceId"
    ]

    class AppliedButInventoryFailed(_AwsBacked):
        def apply(self, *args: Any) -> ApplyResult:
            return ApplyResult(outputs={"instance_id": iid})

        def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
            raise ProvisioningError("aws_unavailable", "temporary inventory failure")

    Worker(h.settings, h.db, AppliedButInventoryFailed(h), clock=h.clock).run_once()
    assert _detail(h, d["id"])["status"] == "recovery_required"
    with h.db.read() as conn:
        ids = [
            r[0]
            for r in conn.execute(
                "SELECT resource_id FROM deployment_resources WHERE deployment_id = ?", (d["id"],)
            )
        ]
    assert iid in ids
    # State and tags never held the VM: the recorded ID still blocks a false deletion.
    _, pending = _replan(h, _AwsBacked(h), d["id"], "deletion-plan")
    assert pending["status"] == "recovery_required"
    assert iid in pending["current_plan"]["error"]["message"]


def test_r2_2_evidence_file_survives_database_contention(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    monkeypatch.setattr(database, "BUSY_TIMEOUT_MS", 20)
    blocker = sqlite3.connect(h.settings.database_path, isolation_level=None)

    class LockedAfterApply(SimulatedProvisioner):
        def apply(self, *args: Any) -> ApplyResult:
            result = super().apply(*args)
            blocker.execute("BEGIN IMMEDIATE")
            return result

    worker = Worker(h.settings, h.db, LockedAfterApply(h.settings.data_dir), clock=h.clock)
    worker.write_retry_delays = (0.01,)
    try:
        with pytest.raises(ServiceUnavailable):
            worker.run_once()
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    evidence = h.settings.workdir_root / d["id"] / "identities.jsonl"
    assert evidence.exists()
    recorded = {json.loads(line)["id"] for line in evidence.read_text().splitlines()}
    assert any(i.startswith("i-") for i in recorded)
    assert worker.run_once() is False  # stranded job recovered, evidence imported
    with h.db.read() as conn:
        ids = {
            r[0]
            for r in conn.execute(
                "SELECT resource_id FROM deployment_resources WHERE deployment_id = ?", (d["id"],)
            )
        }
    assert recorded <= ids
    assert _detail(h, d["id"])["status"] == "recovery_required"


# -------------------- R2-3: migrated deployments and undiscoverable root disks


def _schema_v1_deployment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, iid: str, volume: str | None = None
) -> tuple[Any, Database, str]:
    settings = make_settings(tmp_path)
    db = Database(settings.database_path)
    migrations = database._migration_files()
    with monkeypatch.context() as m:
        m.setattr(database, "_migration_files", lambda: migrations[:1])
        assert db.migrate() == [1]
    dep = "dep_" + "b" * 32
    now = to_db_time(FakeClock()())
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, instance_id, apply_attempted, created_at, updated_at) VALUES "
            "(?, 'dev:alice', 'demo', 8, 'us-east-1', 't3.micro', 'simulated', 'active', ?, 1, "
            "?, ?)",
            (dep, iid, now, now),
        )
    assert db.migrate() == [2, 3]
    if volume:
        with db.transaction() as conn:
            conn.execute("UPDATE deployments SET root_volume_id = ? WHERE id = ?", (volume, dep))
    return settings, db, dep


def test_r2_3_migration_backfills_known_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_path)
    migrations = database._migration_files()
    with monkeypatch.context() as m:
        m.setattr(database, "_migration_files", lambda: migrations[:2])
        assert db.migrate() == [1, 2]
    dep, now = "dep_" + "c" * 32, "2026-10-29T12:00:00+00:00"
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, instance_id, security_group_id, root_volume_id, created_at, "
            "updated_at) VALUES (?, 'dev:a', 'demo', 8, 'us-east-1', 't3.micro', 'simulated', "
            "'active', 'i-0aaaaaaaaaaaaaaa1', 'sg-0aaaaaaaaaaaaaaa1', 'vol-0aaaaaaaaaaaaaaa1', "
            "?, ?)",
            (dep, now, now),
        )
        conn.execute(
            "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
            "config_hash, region, state_key, template_version, created_at, "
            "prior_resource_ids_json) VALUES ('plan_x', ?, 'dev:a', 'create', 'applied', "
            "'simulated', 'h', 'us-east-1', 'k', 'v', ?, ?)",
            (dep, now, json.dumps(["i-0bbbbbbbbbbbbbbb2", "vol-0bbbbbbbbbbbbbbb2"])),
        )
    assert db.migrate() == [3]
    with db.read() as conn:
        known = IdentityLedger.known(conn, dep)
    assert known.instances == {"i-0aaaaaaaaaaaaaaa1", "i-0bbbbbbbbbbbbbbb2"}
    assert known.volumes["vol-0aaaaaaaaaaaaaaa1"] == "i-0aaaaaaaaaaaaaaa1"
    assert "vol-0bbbbbbbbbbbbbbb2" in known.volumes
    assert known.groups == {"sg-0aaaaaaaaaaaaaaa1"}


def _client(settings: Any, db: Database, clock: FakeClock) -> Any:
    from types import SimpleNamespace

    from unitcompute.api.app import build_container, create_app

    container = build_container(settings, deployments=DeploymentService(db, settings, clock=clock))
    client = TestClient(create_app(settings, container))
    return client, SimpleNamespace(settings=settings, db=db, client=client, clock=clock)


def test_r2_3_unknown_root_disk_blocks_deletion_until_acknowledged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, vid = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    ec2.terminate_instances(InstanceIds=[iid])  # root-disk mapping is gone after this
    clock = FakeClock()
    client, h = _client(settings, db, clock)
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        approve_current(h, pending)
        Worker(settings, db, _AwsBacked(h), clock=clock).run_once()
        final = _detail(h, dep)
        assert final["status"] == "recovery_required"
        assert final["latest_job"]["error"]["code"] == "identity_incomplete"
        assert ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"
        assert (
            client.post(
                "/deployments", json={"name": "next", "disk_gib": 8}, headers=auth()
            ).status_code
            == 409
        )

        from unitcompute.admin import main as admin

        monkeypatch.setenv("UNITCOMPUTE_DATA_DIR", str(settings.data_dir))
        monkeypatch.setenv("UNITCOMPUTE_PROVISIONER", "simulated")
        assert (
            admin(
                [
                    "acknowledge-root-disk",
                    dep,
                    "i-0123456789abcdef0",
                    "--operator",
                    "op",
                    "--reason",
                    "x",
                ]
            )
            == 1
        )  # unknown instance is refused
        assert (
            admin(
                [
                    "acknowledge-root-disk",
                    dep,
                    iid,
                    "--operator",
                    "ops-oncall",
                    "--reason",
                    "CloudTrail DeleteVolume confirmed",
                ]
            )
            == 0
        )
        ec2.delete_volume(VolumeId=vid)  # the operator cleaned the disk up out of band
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        approve_current(h, pending)
        Worker(settings, db, _AwsBacked(h), clock=clock).run_once()
        assert _detail(h, dep)["status"] == "deleted"
        with db.read() as conn:
            actions = [r[0] for r in conn.execute("SELECT action FROM audit_events")]
        assert "identity.root_disk_acknowledged" in actions


def test_r2_3_live_instance_disk_is_discovered_and_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, vid = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    clock = FakeClock()
    client, h = _client(settings, db, clock)
    with client:
        # Planning sees the live, recorded VM outside Terraform state and refuses; while
        # doing so it discovers and records the root disk identity.
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["status"] == "plan_failed"
        with db.read() as conn:
            known = IdentityLedger.known(conn, dep)
        assert known.volumes.get(vid) == iid
        assert known.instances_without_root_disk() == []


# ------------------------------------------- R2-5: readiness during previews


def test_r2_5_readiness_keeps_refreshing_during_previews(harness: Harness) -> None:
    h = harness
    d = launch(h)
    assert d["access"]["ready"] is True
    calls: list[str] = []

    class Offline(SimulatedProvisioner):
        def connection_readiness(self, instance_id: str) -> Readiness:
            calls.append(instance_id)
            return Readiness("stopped", "ConnectionLost")

    worker, pending = _replan(h, Offline(h.settings.data_dir), d["id"], "deletion-plan")
    assert pending["status"] == "awaiting_deletion_approval"
    h.clock.advance(days=1)
    worker.housekeeping()
    after = _detail(h, d["id"])
    assert calls
    assert after["access"]["ready"] is False
    assert after["resources"]["connection"]["ssm_ping_status"] == "ConnectionLost"


def test_r2_5_stale_observation_is_not_presented_as_ready(harness: Harness) -> None:
    h = harness
    d = launch(h)
    assert d["access"]["ready"] is True
    h.clock.advance(seconds=2 * h.settings.readiness_refresh_seconds + 1)
    after = _detail(h, d["id"])
    assert after["access"]["ready"] is False
    assert after["resources"]["connection"]["stale"] is True
    assert any("stale" in r for r in after["access"]["requirements"])
