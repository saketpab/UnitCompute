"""The configurable region, and the execution policies for the lifecycle operations.

IAM here is evidence about policy *text* evaluated by a small offline evaluator
(tests/iam_eval.py), never about what AWS accepts.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import iam_eval
from conftest import Harness, make_settings
from test_config_and_auth import TERRAFORM_SETTINGS
from test_review_round2 import ALICE_DEP, BOB_DEP, _context, _placeholders, _role
from unitcompute import config, pricing
from unitcompute.pricing import PRICE_SNAPSHOT, estimate_monthly_cost
from unitcompute.provisioning.aws import packed_session_policy, session_policy
from unitcompute.provisioning.base import DeploymentSpec
from unitcompute.provisioning.policy import evaluate_plan
from unitcompute.provisioning.terraform import build_tfvars

ROOT = Path(__file__).resolve().parents[1]
SECOND = "eu-west-1"


@pytest.fixture
def second_region(monkeypatch: pytest.MonkeyPatch) -> str:
    """Register a second region the way an operator-reviewed code change would."""
    monkeypatch.setattr(config, "SUPPORTED_REGIONS", config.SUPPORTED_REGIONS | {SECOND})
    snapshot = replace(PRICE_SNAPSHOT, region=SECOND, version=f"{SECOND}/test-only")
    monkeypatch.setitem(pricing.PRICE_SNAPSHOTS, SECOND, snapshot)
    return SECOND


# ---------------------------------------------------------------------- region


def test_the_default_region_is_us_east_1(tmp_path: Path) -> None:
    assert make_settings(tmp_path).aws_region == "us-east-1"


@pytest.mark.parametrize("region", ["US-EAST-1", "us-east", "../etc", "us-east-1; rm", "x", ""])
def test_malformed_regions_are_rejected(tmp_path: Path, region: str) -> None:
    with pytest.raises(ValidationError, match="look like an AWS region"):
        make_settings(tmp_path, aws_region=region)


def test_a_well_formed_region_without_a_reviewed_snapshot_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="supported regions: us-east-1"):
        make_settings(tmp_path, aws_region=SECOND)


def test_a_registered_region_flows_through_configuration_prices_and_plans(
    tmp_path: Path, second_region: str
) -> None:
    settings = make_settings(tmp_path, aws_region=second_region)
    assert settings.aws_region == second_region
    estimate = estimate_monthly_cost(8, region=second_region)
    assert estimate.price_snapshot["region"] == second_region
    assert estimate.price_snapshot["version"] == f"{second_region}/test-only"
    spec = DeploymentSpec(
        "dep_" + "a" * 32, "0123456789abcdef", "demo", 8, second_region, "t3.micro"
    )
    from test_policy import TARGETS

    assert build_tfvars(spec, TARGETS, "ami-0123456789abcdef0")["region"] == second_region
    with pytest.raises(KeyError):
        estimate_monthly_cost(8, region="ap-south-1")


def test_the_session_policy_follows_the_configured_region(
    tmp_path: Path, second_region: str
) -> None:
    settings = make_settings(tmp_path / "s", **{**TERRAFORM_SETTINGS, "aws_region": second_region})
    for role in ("plan", "apply"):
        text = json.dumps(session_policy(settings, role, ALICE_DEP))
        assert second_region in text and "us-east-1" not in text
    assert second_region in json.dumps(session_policy(settings, "plan", None))


def test_iam_documents_have_no_hard_coded_region() -> None:
    for name in ("apply-role-policy.json", "plan-role-policy.json"):
        text = (ROOT / "docs" / "iam" / name).read_text()
        assert "us-east-1" not in text and "${region}" in text


def test_role_policy_regional_arns_follow_the_placeholder(
    tmp_path: Path, second_region: str
) -> None:
    settings = make_settings(tmp_path, **{**TERRAFORM_SETTINGS, "aws_region": second_region})
    placeholders = _placeholders(settings)
    role = _role("apply-role-policy.json")
    instance = f"arn:aws:ec2:{second_region}:{settings.aws_account_id}:instance/i-0123456789abcdef0"
    context = _context(
        ALICE_DEP,
        **{
            "aws:RequestedRegion": second_region,
            "ec2:ResourceTag/ManagedBy": "unitcompute",
            "ec2:ResourceTag/UnitComputeDeployment": ALICE_DEP,
        },
    )
    assert iam_eval.allowed([role], "ec2:StopInstances", instance, context, placeholders)
    other = instance.replace(second_region, "us-east-1")
    assert not iam_eval.allowed([role], "ec2:StopInstances", other, context, placeholders)


def test_the_agent_uses_the_configured_region(harness: Harness, second_region: str) -> None:
    from unitcompute.agent.service import build_tools, system_prompt

    assert "region eu-west-1" in system_prompt(second_region)
    assert "us-east-1" not in system_prompt(second_region)
    from unitcompute.agent.service import _RunContext
    from unitcompute.auth import Principal

    ctx = _RunContext()
    tools = {
        t.name: t
        for t in build_tools(
            Principal(subject="dev:alice", auth_method="dev"),
            harness.container.deployments,
            ctx,
            second_region,
        )
    }
    tools["check_deployment_config"].invoke({"name": "my-vm", "disk_gib": 8})
    assert ctx.proposal is not None and ctx.proposal.region == second_region


# ------------------------------------------------------------------- IAM actions

TAGGED = {"ec2:ResourceTag/ManagedBy": "unitcompute"}


def _resource(settings: Any, kind: str) -> str:
    return f"arn:aws:ec2:us-east-1:{settings.aws_account_id}:{kind}/{kind[:3]}-0123456789abcdef0"


def _allowed(
    settings: Any, action: str, kind: str, owner: str, tag_keys: str | None = None, **extra: str
) -> bool:
    context = _context(ALICE_DEP, **TAGGED, **extra)
    context["ec2:ResourceTag/UnitComputeDeployment"] = owner
    if tag_keys is not None:
        context["aws:TagKeys"] = tag_keys
    role = _role("apply-role-policy.json")
    session = session_policy(settings, "apply", ALICE_DEP)
    return iam_eval.allowed(
        [role, session], action, _resource(settings, kind), context, _placeholders(settings)
    )


@pytest.fixture
def settings(tmp_path: Path) -> Any:
    return make_settings(tmp_path, **TERRAFORM_SETTINGS)


@pytest.mark.parametrize(
    ("action", "kind"),
    [
        ("ec2:StopInstances", "instance"),
        ("ec2:StartInstances", "instance"),
        ("ec2:ModifyVolume", "volume"),
    ],
)
def test_lifecycle_actions_work_only_on_the_deployments_own_tagged_resources(
    settings: Any, action: str, kind: str
) -> None:
    assert _allowed(settings, action, kind, ALICE_DEP)
    assert not _allowed(settings, action, kind, BOB_DEP)


def test_untagged_resources_cannot_be_stopped_started_or_resized(settings: Any) -> None:
    role = _role("apply-role-policy.json")
    session = session_policy(settings, "apply", ALICE_DEP)
    for action, kind in (
        ("ec2:StopInstances", "instance"),
        ("ec2:StartInstances", "instance"),
        ("ec2:ModifyVolume", "volume"),
    ):
        context = _context(ALICE_DEP)  # no resource tags at all
        assert not iam_eval.allowed(
            [role, session], action, _resource(settings, kind), context, _placeholders(settings)
        )


@pytest.mark.parametrize("kind", ["instance", "volume", "security-group"])
def test_renaming_may_edit_only_the_name_tag(settings: Any, kind: str) -> None:
    for action in ("ec2:CreateTags", "ec2:DeleteTags"):
        assert _allowed(settings, action, kind, ALICE_DEP, tag_keys="Name"), (action, kind)
        assert not _allowed(settings, action, kind, BOB_DEP, tag_keys="Name"), (action, kind)
        for keys in ("ManagedBy", "UnitComputeDeployment", "Name,ManagedBy", "Owner"):
            assert not _allowed(settings, action, kind, ALICE_DEP, tag_keys=keys), (action, keys)


def test_each_policy_alone_enforces_the_name_only_rule(settings: Any) -> None:
    role = _role("apply-role-policy.json")
    session = session_policy(settings, "apply", ALICE_DEP)
    placeholders = _placeholders(settings)
    for policy in (role, session):
        for keys, expected in (("Name", True), ("ManagedBy", False), ("Name,ManagedBy", False)):
            context = _context(ALICE_DEP, **TAGGED)
            context["ec2:ResourceTag/UnitComputeDeployment"] = ALICE_DEP
            context["aws:TagKeys"] = keys
            result = iam_eval.allowed(
                [policy], "ec2:CreateTags", _resource(settings, "instance"), context, placeholders
            )
            assert result is expected, (keys, "role" if policy is role else "session")


def test_the_plan_role_cannot_mutate_anything(settings: Any) -> None:
    plan_role = _role("plan-role-policy.json")
    session = session_policy(settings, "plan", ALICE_DEP)
    for action, kind in (
        ("ec2:StopInstances", "instance"),
        ("ec2:StartInstances", "instance"),
        ("ec2:ModifyVolume", "volume"),
        ("ec2:CreateTags", "instance"),
        ("ec2:DeleteTags", "instance"),
        ("ec2:TerminateInstances", "instance"),
    ):
        context = _context(ALICE_DEP, **TAGGED, **{"aws:TagKeys": "Name"})
        context["ec2:ResourceTag/UnitComputeDeployment"] = ALICE_DEP
        assert not iam_eval.allowed(
            [plan_role, session],
            action,
            _resource(settings, kind),
            context,
            _placeholders(settings),
        ), action


def test_volume_modification_is_readable_for_the_resize_wait() -> None:
    role = _role("apply-role-policy.json")
    reads = next(s for s in role["Statement"] if s["Sid"] == "ReadOnlyEc2InApprovedRegion")
    assert "ec2:DescribeVolumesModifications" in reads["Action"]


def test_the_session_policy_fits_the_sts_limit_for_the_longest_state_bucket(tmp_path: Path) -> None:
    longest = "a" + "b" * 61 + "c"  # 63 characters, the S3 maximum
    settings = make_settings(tmp_path, **{**TERRAFORM_SETTINGS, "state_bucket": longest})
    for role in ("plan", "apply"):
        assert len(packed_session_policy(settings, role, ALICE_DEP)) <= 2048


def test_lifecycle_policy_does_not_grant_iam_or_bootstrap_access() -> None:
    text = (ROOT / "docs" / "iam" / "apply-role-policy.json").read_text()
    role = json.loads(text)
    assert any(s["Sid"] == "NoIamChanges" for s in role["Statement"])
    assert any(s["Sid"] == "NeverTouchBootstrapState" for s in role["Statement"])
    granted = {
        a
        for s in role["Statement"]
        if s["Effect"] == "Allow"
        for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
    }
    assert not any(a.startswith(("iam:", "sts:")) for a in granted - {"iam:PassRole"})
    assert "ec2:ModifyInstanceAttribute" not in granted  # no instance-type change path
    assert evaluate_plan is not None
