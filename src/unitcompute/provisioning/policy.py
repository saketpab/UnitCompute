"""Inspect ``terraform show -json`` output before a plan can be offered for approval.

The policy is an allow-list: only the two template resources, only the expected actions,
only the reviewed attribute values, and only resources tagged for this deployment. Any
deviation rejects the plan; nothing here tries to "fix" a plan.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from unitcompute.provisioning.base import (
    MANAGED_BY_VALUE,
    TAG_DEPLOYMENT,
    TAG_MANAGED_BY,
    TAG_OWNER,
    TAG_TEMPLATE,
    TEMPLATE_VERSION,
    DeploymentSpec,
    NetworkTargets,
    OwnedResource,
    PlanKind,
)

AWS_PROVIDER = "registry.terraform.io/hashicorp/aws"
INSTANCE = "aws_instance.vm"
SECURITY_GROUP = "aws_security_group.vm"
EXPECTED_TYPES = {INSTANCE: "aws_instance", SECURITY_GROUP: "aws_security_group"}
ALLOWED_ACTIONS: dict[PlanKind, set[tuple[str, ...]]] = {
    "create": {("create",), ("no-op",)},
    "destroy": {("delete",)},
}
EXPECTED_EGRESS = {
    "from_port": 443,
    "to_port": 443,
    "protocol": "tcp",
    "cidr_blocks": ["0.0.0.0/0"],
    "ipv6_cidr_blocks": [],
    "prefix_list_ids": [],
    "security_groups": [],
    "self": False,
}
DATA_LOSS_WARNING = (
    "Deleting terminates the VM and permanently deletes its root disk. Data on the disk "
    "cannot be recovered and no snapshot is taken."
)


@dataclass
class PolicyResult:
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    changes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.violations


def expected_tags(spec: DeploymentSpec) -> dict[str, str]:
    return {
        TAG_MANAGED_BY: MANAGED_BY_VALUE,
        TAG_DEPLOYMENT: spec.deployment_id,
        TAG_OWNER: spec.owner_tag,
        TAG_TEMPLATE: TEMPLATE_VERSION,
    }


def _first(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0]
    return {}


def _check(violations: list[str], condition: bool, message: str) -> None:
    if not condition:
        violations.append(message)


def _tags_ok(values: dict[str, Any], spec: DeploymentSpec, name: str) -> bool:
    tags = values.get("tags")
    if not isinstance(tags, dict):
        return False
    wanted = {**expected_tags(spec), "Name": name}
    return tags == wanted


def _owned_by_deployment(values: dict[str, Any], spec: DeploymentSpec) -> bool:
    tags = values.get("tags")
    return (
        isinstance(tags, dict)
        and tags.get(TAG_DEPLOYMENT) == spec.deployment_id
        and tags.get(TAG_MANAGED_BY) == MANAGED_BY_VALUE
    )


def _check_instance(
    after: dict[str, Any], spec: DeploymentSpec, targets: NetworkTargets, ami_id: str | None
) -> list[str]:
    v: list[str] = []
    _check(
        v, ami_id is not None and after.get("ami") == ami_id, "instance AMI is not the frozen AMI"
    )
    _check(v, after.get("instance_type") == spec.instance_type, "unexpected instance type")
    _check(v, after.get("subnet_id") == targets.subnet_id, "instance is not in the approved subnet")
    _check(
        v,
        after.get("iam_instance_profile") == targets.instance_profile_name,
        "instance profile is not the approved SSM profile",
    )
    _check(v, after.get("associate_public_ip_address") is True, "public IPv4 must be auto-assigned")
    _check(v, after.get("user_data") is None, "user data is not allowed")
    _check(v, after.get("user_data_base64") is None, "user data is not allowed")
    _check(v, after.get("launch_template") in (None, []), "launch templates are not allowed")
    _check(v, after.get("ebs_block_device") in (None, []), "extra EBS volumes are not allowed")
    metadata = _first(after.get("metadata_options"))
    _check(
        v, metadata.get("http_tokens") == "required", "IMDSv2 (http_tokens=required) is required"
    )
    _check(v, metadata.get("http_endpoint") == "enabled", "metadata endpoint must stay enabled")
    _check(v, metadata.get("http_put_response_hop_limit") == 1, "IMDS hop limit must be 1")
    credits = _first(after.get("credit_specification"))
    _check(v, credits.get("cpu_credits") == "standard", "cpu_credits must be standard")
    root = _first(after.get("root_block_device"))
    _check(v, root.get("volume_type") == "gp3", "root volume must be gp3")
    _check(v, root.get("volume_size") == spec.disk_gib, "root volume size does not match request")
    _check(v, root.get("encrypted") is True, "root volume must be encrypted")
    _check(v, root.get("delete_on_termination") is True, "root volume must delete on termination")
    _check(
        v,
        isinstance(root.get("tags"), dict)
        and root["tags"] == {**expected_tags(spec), "Name": f"unitcompute-{spec.name}-root"},
        "root volume tags do not match this deployment",
    )
    _check(v, after.get("region") in (None, spec.region), "instance region is not approved")
    _check(v, _tags_ok(after, spec, f"unitcompute-{spec.name}"), "instance tags do not match")
    return v


def _check_security_group(
    after: dict[str, Any], spec: DeploymentSpec, targets: NetworkTargets
) -> list[str]:
    v: list[str] = []
    _check(v, after.get("vpc_id") == targets.vpc_id, "security group is not in the approved VPC")
    _check(v, after.get("ingress") == [], "security group must have no inbound rules")
    egress = after.get("egress")
    ok_egress = (
        isinstance(egress, list)
        and len(egress) == 1
        and isinstance(egress[0], dict)
        and all(egress[0].get(key) == value for key, value in EXPECTED_EGRESS.items())
    )
    _check(v, ok_egress, "security group egress must be HTTPS (tcp/443) only")
    _check(v, after.get("region") in (None, spec.region), "security group region is not approved")
    _check(v, _tags_ok(after, spec, f"unitcompute-{spec.name}"), "security group tags do not match")
    return v


def _summary(address: str, values: dict[str, Any], kind: PlanKind) -> dict[str, Any]:
    if address == INSTANCE:
        root = _first(values.get("root_block_device"))
        return {
            "instance_type": values.get("instance_type"),
            "ami_id": values.get("ami"),
            "root_disk_gib": root.get("volume_size"),
            "root_disk_encrypted": root.get("encrypted"),
            "imdsv2_required": _first(values.get("metadata_options")).get("http_tokens")
            == "required",
            "public_ipv4": values.get("associate_public_ip_address"),
            "access": "SSM Session Manager only (no inbound ports)",
            **({"data_loss": True} if kind == "destroy" else {}),
        }
    return {"inbound_rules": 0, "outbound": "tcp/443 to 0.0.0.0/0"}


ALLOWED_PROVIDER_ARGUMENTS = {"region", "allowed_account_ids"}


def _check_configuration(plan: dict[str, Any]) -> list[str]:
    """Defence in depth on top of the template hash: no extra modules, data sources,
    providers, or provider arguments such as endpoint overrides or inline credentials."""
    v: list[str] = []
    configuration = plan.get("configuration") or {}
    providers = configuration.get("provider_config") or {}
    if set(providers) != {"aws"}:
        v.append("plan configures unexpected providers")
    aws = providers.get("aws") or {}
    if aws.get("full_name") != AWS_PROVIDER or aws.get("alias"):
        v.append("plan uses an unexpected AWS provider configuration")
    if not set(aws.get("expressions") or {}) <= ALLOWED_PROVIDER_ARGUMENTS:
        v.append("plan sets provider arguments outside the reviewed template")
    root = configuration.get("root_module") or {}
    if root.get("module_calls"):
        v.append("plan calls modules outside the reviewed template")
    addresses = {r.get("address") for r in root.get("resources") or []}
    if not addresses <= set(EXPECTED_TYPES):
        v.append("plan configuration declares unexpected resources or data sources")
    return v


def _prior_resource_ids(plan: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    root = plan.get("prior_state", {}).get("values", {}).get("root_module", {})
    for resource in root.get("resources", []) or []:
        values = resource.get("values") or {}
        if isinstance(values.get("id"), str):
            ids.add(values["id"])
        for device in values.get("root_block_device") or []:
            if isinstance(device, dict) and isinstance(device.get("volume_id"), str):
                ids.add(device["volume_id"])
    return ids


def evaluate_plan(
    plan: dict[str, Any],
    *,
    kind: PlanKind,
    spec: DeploymentSpec,
    targets: NetworkTargets,
    ami_id: str | None,
    inventory: Iterable[OwnedResource],
) -> PolicyResult:
    result = PolicyResult()
    v = result.violations
    if plan.get("errored") is not False:
        v.append("terraform reported an errored or incomplete plan")
    if plan.get("complete") is False:
        v.append("terraform reported an incomplete plan")

    variables = plan.get("variables") or {}
    expected_vars: dict[str, Any] = {
        "region": spec.region,
        "account_id": targets.account_id,
        "deployment_id": spec.deployment_id,
        "owner_tag": spec.owner_tag,
        "name": spec.name,
        "disk_gib": spec.disk_gib,
        "instance_type": spec.instance_type,
        "vpc_id": targets.vpc_id,
        "subnet_id": targets.subnet_id,
        "instance_profile_name": targets.instance_profile_name,
    }
    if kind == "create":
        expected_vars["ami_id"] = ami_id
    for name, value in expected_vars.items():
        if (variables.get(name) or {}).get("value") != value:
            v.append(f"plan variable {name!r} does not match the server configuration")
    unknown_vars = set(variables) - set(expected_vars) - {"ami_id"}
    if unknown_vars:
        v.append("plan contains unexpected variables")

    v.extend(_check_configuration(plan))

    seen: dict[str, tuple[str, ...]] = {}
    for change in plan.get("resource_changes") or []:
        address = change.get("address")
        actions = tuple((change.get("change") or {}).get("actions") or ())
        if change.get("mode") != "managed" or address not in EXPECTED_TYPES:
            v.append(f"unexpected resource {address!r} in plan")
            continue
        if change.get("type") != EXPECTED_TYPES[address]:
            v.append(f"unexpected resource type for {address}")
        if change.get("provider_name") != AWS_PROVIDER:
            v.append(f"unexpected provider for {address}")
        if actions not in ALLOWED_ACTIONS[kind]:
            v.append(
                f"action {'/'.join(actions) or 'none'} on {address} is not allowed for a "
                f"{kind} plan"
            )
            continue
        seen[address] = actions
        body = change.get("change") or {}
        before = body.get("before") or {}
        after = body.get("after") or {}
        if actions == ("create",):
            if address == INSTANCE:
                v.extend(_check_instance(after, spec, targets, ami_id))
            else:
                v.extend(_check_security_group(after, spec, targets))
        elif not _owned_by_deployment(before, spec):
            v.append(f"{address} is not tagged as owned by this deployment")
        if actions != ("no-op",):
            values = before if actions == ("delete",) else after
            result.changes.append(
                {
                    "address": address,
                    "resource_type": EXPECTED_TYPES[address],
                    "action": actions[0],
                    "summary": _summary(address, values, kind),
                }
            )

    if kind == "create" and set(seen) != set(EXPECTED_TYPES):
        v.append("create plan must manage exactly one VM and one security group")
    if kind == "destroy":
        result.warnings.append(DATA_LOSS_WARNING)

    known = _prior_resource_ids(plan)
    orphans = sorted(r.resource_id for r in inventory if r.resource_id not in known)
    if orphans:
        v.append(
            "AWS has resources tagged for this deployment that are not in Terraform state "
            f"({', '.join(orphans)}); operator reconciliation is required"
        )
    if plan.get("resource_drift"):
        result.warnings.append(
            "Resources changed outside UnitCompute since the last apply; review carefully."
        )
    return result
