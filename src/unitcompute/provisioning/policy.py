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
INSTANCE_STATE = "aws_ec2_instance_state.vm"
EXPECTED_TYPES = {
    INSTANCE: "aws_instance",
    SECURITY_GROUP: "aws_security_group",
    INSTANCE_STATE: "aws_ec2_instance_state",
}
POWER_STATES = ("running", "stopped")
# "create" plans converge the deployment on its requested spec: they create what is missing,
# update the few attributes below in place, and leave the rest alone. Replacement
# (delete + create) is never allowed: an edit must not destroy the VM or its disk.
ALLOWED_ACTIONS: dict[PlanKind, set[tuple[str, ...]]] = {
    "create": {("create",), ("no-op",), ("update",)},
    "destroy": {("delete",)},
}
# What an in-place update may change, per resource. The VM's name is a tag; its disk can only
# grow (checked separately); its power state is the one attribute of the state resource.
INSTANCE_UPDATE_CHANGES = {"tags", "tags_all", "volume_tags", "root_block_device"}
# Attributes the provider reports as unknown after an in-place update of the above even though
# the reviewed configuration pins them (the template hash is the guard for their values).
INSTANCE_UPDATE_UNKNOWN = {
    "credit_specification",
    "ipv6_addresses",
    "metadata_options",
    "root_block_device",
    "secondary_private_ips",
    "vpc_security_group_ids",
}
SECURITY_GROUP_UPDATE_CHANGES = {"tags", "tags_all"}
INSTANCE_STATE_UPDATE_CHANGES = {"state"}
INSTANCE_STATE_CREATE_FIELDS = {"force", "region", "state", "timeouts"}
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
# Attributes Terraform reports as known for a newly created resource of the reviewed
# template. Anything else in ``after`` means the configuration set an unreviewed argument
# (for example key_name, tenancy, extra network interfaces or custom IOPS).
INSTANCE_CREATE_VALUES: dict[str, Any] = {
    "force_destroy": False,
    "get_password_data": False,
    "hibernation": None,
    "launch_template": [],
    "monitoring": False,
    "source_dest_check": True,
    "timeouts": None,
    "user_data": None,
    "user_data_replace_on_change": False,
}
INSTANCE_CREATE_FIELDS = set(INSTANCE_CREATE_VALUES) | {
    "ami",
    "associate_public_ip_address",
    "credit_specification",
    "iam_instance_profile",
    "instance_type",
    "metadata_options",
    "region",
    "root_block_device",
    "subnet_id",
    "tags",
    "tags_all",
    "volume_tags",
}
ROOT_CREATE_FIELDS = {"delete_on_termination", "encrypted", "tags", "volume_size", "volume_type"}
SECURITY_GROUP_CREATE_FIELDS = {
    "description",
    "egress",
    "ingress",
    "name",
    "region",
    "revoke_rules_on_delete",
    "tags",
    "tags_all",
    "timeouts",
    "vpc_id",
}
# Arguments the reviewed template sets, per resource, in ``configuration``.
CONFIGURED_ARGUMENTS = {
    INSTANCE: {
        "ami",
        "associate_public_ip_address",
        "credit_specification",
        "iam_instance_profile",
        "instance_type",
        "metadata_options",
        "monitoring",
        "root_block_device",
        "subnet_id",
        "tags",
        "volume_tags",
        "vpc_security_group_ids",
    },
    SECURITY_GROUP: {"description", "egress", "ingress", "name", "tags", "vpc_id"},
    INSTANCE_STATE: {"force", "instance_id", "state"},
}
CONFIGURED_BLOCK_ARGUMENTS = {
    # No "tags": root_block_device.tags are applied after launch by a separate CreateTags
    # call, which the tag-on-create IAM policies deny. Volumes are tagged via volume_tags.
    "root_block_device": {
        "volume_type",
        "volume_size",
        "encrypted",
        "delete_on_termination",
    },
    "metadata_options": {
        "http_endpoint",
        "http_tokens",
        "http_put_response_hop_limit",
        "instance_metadata_tags",
    },
    "credit_specification": {"cpu_credits"},
}
CONFIGURATION_RESOURCE_KEYS = {
    "address",
    "expressions",
    "mode",
    "name",
    "provider_config_key",
    "schema_version",
    "type",
}
DEDICATED_GROUP_REFERENCES = ["aws_security_group.vm.id", "aws_security_group.vm"]

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


def _check_instance_create_fields(
    after: dict[str, Any], after_unknown: dict[str, Any], group_id: str | None
) -> list[str]:
    v: list[str] = []
    extra = sorted(set(after) - INSTANCE_CREATE_FIELDS - {"vpc_security_group_ids"})
    if extra:
        v.append(f"instance sets unreviewed attributes: {', '.join(extra)}")
    for key, value in INSTANCE_CREATE_VALUES.items():
        _check(v, after.get(key) == value, f"instance attribute {key} has an unreviewed value")
    _check(v, after.get("tags_all") == after.get("tags"), "instance has unexpected default tags")
    extra_root = sorted(set(_first(after.get("root_block_device"))) - ROOT_CREATE_FIELDS)
    if extra_root:
        v.append(f"root volume sets unreviewed attributes: {', '.join(extra_root)}")
    _check(
        v,
        _first(after.get("root_block_device")).get("tags") in (None, {}),
        "root_block_device.tags are tagged after launch and denied by IAM; use volume_tags",
    )
    v.extend(_check_group_attachment(after, after_unknown, group_id))
    return v


def _check_group_attachment(
    values: dict[str, Any], unknown: dict[str, Any], group_id: str | None
) -> list[str]:
    """The VM must be attached to exactly this deployment's dedicated security group."""
    groups = values.get("vpc_security_group_ids")
    if groups is None and unknown.get("vpc_security_group_ids") is True and group_id is None:
        return []  # created together; the configuration check pins the reference
    if group_id is not None and groups == [group_id]:
        return []
    return ["instance must be attached only to its dedicated security group"]


def _check_instance(
    after: dict[str, Any],
    spec: DeploymentSpec,
    targets: NetworkTargets,
    ami_id: str | None,
    unknown: dict[str, Any] | None = None,
) -> list[str]:
    """Shape of an instance as it will be after the plan. ``unknown`` lists attributes the
    provider cannot predict for an in-place update; the reviewed template pins their values
    (its hash is checked), so they are skipped here rather than failed."""
    pending = unknown or {}
    v: list[str] = []
    _check(v, not after.get("key_name"), "SSH key pairs are not allowed")
    _check(v, after.get("tenancy") in (None, "default"), "only default tenancy is allowed")
    _check(
        v, after.get("network_interface") in (None, []), "extra network interfaces are not allowed"
    )
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
    if pending.get("metadata_options") is not True:
        _check(
            v,
            metadata.get("http_tokens") == "required",
            "IMDSv2 (http_tokens=required) is required",
        )
        _check(v, metadata.get("http_endpoint") == "enabled", "metadata endpoint must stay enabled")
        _check(v, metadata.get("http_put_response_hop_limit") == 1, "IMDS hop limit must be 1")
    credits = _first(after.get("credit_specification"))
    if pending.get("credit_specification") is not True:
        _check(v, credits.get("cpu_credits") == "standard", "cpu_credits must be standard")
    root = _first(after.get("root_block_device"))
    _check(v, root.get("volume_type") == "gp3", "root volume must be gp3")
    _check(v, root.get("volume_size") == spec.disk_gib, "root volume size does not match request")
    _check(v, root.get("encrypted") is True, "root volume must be encrypted")
    _check(v, root.get("delete_on_termination") is True, "root volume must delete on termination")
    root_tags = {**expected_tags(spec), "Name": f"unitcompute-{spec.name}-root"}
    _check(
        v,
        after.get("volume_tags") == root_tags,
        "volumes must be tagged for this deployment at launch (volume_tags)",
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


def _prior_instance_id(plan: dict[str, Any]) -> str | None:
    root = plan.get("prior_state", {}).get("values", {}).get("root_module", {})
    for resource in root.get("resources", []) or []:
        if resource.get("address") == INSTANCE:
            found = (resource.get("values") or {}).get("id")
            return found if isinstance(found, str) else None
    return None


def _owned(
    address: str, values: dict[str, Any], spec: DeploymentSpec, instance_id: str | None
) -> bool:
    """Existing resources must belong to this deployment: tagged for it, or (the power-state
    resource has no tags) attached to this deployment's own instance."""
    if address == INSTANCE_STATE:
        return instance_id is not None and values.get("instance_id") == instance_id
    return _owned_by_deployment(values, spec)


def _check_instance_state(values: dict[str, Any], spec: DeploymentSpec) -> list[str]:
    v: list[str] = []
    _check(
        v,
        values.get("state") == spec.power_state,
        f"power state does not match the request ({spec.power_state})",
    )
    _check(v, values.get("force") in (None, False), "forced power changes are not allowed")
    _check(v, values.get("region") in (None, spec.region), "power-state region is not approved")
    return v


def _check_instance_state_create(
    after: dict[str, Any], spec: DeploymentSpec, instance_id: str | None
) -> list[str]:
    v = _check_instance_state(after, spec)
    extra = sorted(set(after) - INSTANCE_STATE_CREATE_FIELDS)
    if extra:
        v.append(f"power state sets unreviewed attributes: {', '.join(extra)}")
    if after.get("instance_id") not in (None, instance_id):
        v.append("power state must target this deployment's own instance")
    return v


def _changed_keys(
    before: dict[str, Any], after: dict[str, Any], unknown: dict[str, Any]
) -> set[str]:
    return {
        k for k in set(before) | set(after) if before.get(k) != after.get(k) and not unknown.get(k)
    }


def _check_update(
    address: str,
    before: dict[str, Any],
    after: dict[str, Any],
    unknown: dict[str, Any],
    spec: DeploymentSpec,
    group_id: str | None,
    targets: NetworkTargets,
    ami_id: str | None,
) -> list[str]:
    """An in-place update is allowed only for the three edits the service offers: the name
    (tags), a larger disk, and the power state. Everything else must be unchanged."""
    v: list[str] = []
    changed = _changed_keys(before, after, unknown)
    unknown_keys = {k for k, u in unknown.items() if u}
    if address == INSTANCE:
        extra = sorted(changed - INSTANCE_UPDATE_CHANGES)
        if extra:
            v.append(f"instance update changes unreviewed attributes: {', '.join(extra)}")
        unexpected = sorted(unknown_keys - INSTANCE_UPDATE_UNKNOWN)
        if unexpected:
            v.append(
                f"instance update leaves unreviewed attributes unknown: {', '.join(unexpected)}"
            )
        _check(
            v, after.get("tags_all") == after.get("tags"), "instance has unexpected default tags"
        )
        _check(v, unknown.get("root_block_device") is not True, "root volume size is not known")
        v.extend(_check_instance(after, spec, targets, ami_id, unknown))
        old_size = _first(before.get("root_block_device")).get("volume_size")
        size = _first(after.get("root_block_device")).get("volume_size")
        _check(
            v,
            isinstance(size, int) and isinstance(old_size, int) and size >= old_size,
            "the root disk can only grow",
        )
        groups = after.get("vpc_security_group_ids")
        if unknown.get("vpc_security_group_ids") is not True:
            _check(
                v,
                group_id is not None and groups == [group_id],
                "instance must be attached only to its dedicated security group",
            )
    elif address == SECURITY_GROUP:
        extra = sorted(changed - SECURITY_GROUP_UPDATE_CHANGES)
        if extra:
            v.append(f"security group update changes unreviewed attributes: {', '.join(extra)}")
        _check(v, not unknown_keys, "security group update leaves attributes unknown")
        _check(
            v, _tags_ok(after, spec, f"unitcompute-{spec.name}"), "security group tags do not match"
        )
    else:
        extra = sorted(changed - INSTANCE_STATE_UPDATE_CHANGES)
        if extra:
            v.append(f"power state update changes unreviewed attributes: {', '.join(extra)}")
        _check(v, not unknown_keys, "power state update leaves attributes unknown")
        v.extend(_check_instance_state(after, spec))
        _check(
            v,
            before.get("state") in POWER_STATES and after.get("state") in POWER_STATES,
            "unexpected power state",
        )
    return v


def _diff(address: str, before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Human-readable before/after of what an update changes."""
    out: dict[str, Any] = {}
    if address == INSTANCE:
        old, new = _first(before.get("root_block_device")), _first(after.get("root_block_device"))
        if old.get("volume_size") != new.get("volume_size"):
            out["disk_gib"] = [old.get("volume_size"), new.get("volume_size")]
    if address in (INSTANCE, SECURITY_GROUP):
        old_name = (before.get("tags") or {}).get("Name")
        new_name = (after.get("tags") or {}).get("Name")
        if old_name != new_name:
            prefix = "unitcompute-"
            out["name"] = [
                str(old_name).removeprefix(prefix) if old_name else None,
                str(new_name).removeprefix(prefix) if new_name else None,
            ]
    if address == INSTANCE_STATE and before.get("state") != after.get("state"):
        out["power_state"] = [before.get("state"), after.get("state")]
    return out


def _summary(address: str, values: dict[str, Any], kind: PlanKind) -> dict[str, Any]:
    if address == INSTANCE_STATE:
        return {"power_state": values.get("state")}
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
    resources = root.get("resources") or []
    addresses = {r.get("address") for r in resources}
    if not addresses <= set(EXPECTED_TYPES):
        v.append("plan configuration declares unexpected resources or data sources")
    for resource in resources:
        address = resource.get("address")
        if resource.get("provisioners"):
            v.append(f"{address} declares provisioners, which are not allowed")
        if not set(resource) <= CONFIGURATION_RESOURCE_KEYS:
            v.append(f"{address} uses unreviewed meta-arguments")
        expressions = resource.get("expressions") or {}
        allowed = CONFIGURED_ARGUMENTS.get(address, set())
        if set(expressions) != allowed:
            v.append(f"{address} configures unreviewed arguments")
        for block, keys in CONFIGURED_BLOCK_ARGUMENTS.items():
            for entry in expressions.get(block) or []:
                if isinstance(entry, dict) and not set(entry) <= keys:
                    v.append(f"{address} {block} configures unreviewed arguments")
        if address == INSTANCE:
            refs = (expressions.get("vpc_security_group_ids") or {}).get("references")
            if refs != DEDICATED_GROUP_REFERENCES:
                v.append("instance must reference only its dedicated security group")
    return v


def _prior_group_id(plan: dict[str, Any]) -> str | None:
    root = plan.get("prior_state", {}).get("values", {}).get("root_module", {})
    for resource in root.get("resources", []) or []:
        if resource.get("address") == SECURITY_GROUP:
            group = (resource.get("values") or {}).get("id")
            return group if isinstance(group, str) else None
    return None


def prior_resource_identities(plan: dict[str, Any]) -> list[tuple[str, str | None]]:
    """(resource_id, parent_instance_id) for everything in Terraform's prior state."""
    found: list[tuple[str, str | None]] = []
    root = plan.get("prior_state", {}).get("values", {}).get("root_module", {})
    for resource in root.get("resources", []) or []:
        values = resource.get("values") or {}
        instance = values.get("id") if resource.get("address") == INSTANCE else None
        if isinstance(values.get("id"), str):
            found.append((values["id"], None))
        for device in values.get("root_block_device") or []:
            if isinstance(device, dict) and isinstance(device.get("volume_id"), str):
                found.append((device["volume_id"], instance if isinstance(instance, str) else None))
    return found


def prior_resource_ids(plan: dict[str, Any]) -> set[str]:
    """IDs Terraform state knows for this deployment (instance, root volume, group)."""
    return _prior_resource_ids(plan)


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
        "power_state": spec.power_state,
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

    group_id = _prior_group_id(plan)
    instance_id = _prior_instance_id(plan)
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
        unknown = body.get("after_unknown") or {}
        if actions == ("create",):
            if address == INSTANCE:
                v.extend(_check_instance(after, spec, targets, ami_id))
                v.extend(_check_instance_create_fields(after, unknown, group_id))
            elif address == SECURITY_GROUP:
                extra = sorted(set(after) - SECURITY_GROUP_CREATE_FIELDS)
                if extra:
                    v.append(f"security group sets unreviewed attributes: {', '.join(extra)}")
                v.extend(_check_security_group(after, spec, targets))
            else:
                v.extend(_check_instance_state_create(after, spec, instance_id))
        elif not _owned(address, before, spec, instance_id):
            v.append(f"{address} is not tagged as owned by this deployment")
        elif actions == ("no-op",):
            # Existing resources must still match the reviewed shape, not just be owned.
            if address == INSTANCE:
                v.extend(_check_instance(after, spec, targets, ami_id))
                v.extend(_check_group_attachment(after, {}, group_id))
            elif address == SECURITY_GROUP:
                v.extend(_check_security_group(after, spec, targets))
            else:
                v.extend(_check_instance_state(after, spec))
        elif actions == ("update",):
            v.extend(
                _check_update(address, before, after, unknown, spec, group_id, targets, ami_id)
            )
        # An update that changes nothing the user can see (the provider refreshing computed
        # attributes) is validated above but not listed as a change.
        invisible = actions == ("update",) and not _diff(address, before, after)
        if actions != ("no-op",) and not invisible:
            values = before if actions == ("delete",) else after
            summary = _summary(address, values, kind)
            if actions == ("update",):
                summary["changes"] = _diff(address, before, after)
            result.changes.append(
                {
                    "address": address,
                    "resource_type": EXPECTED_TYPES[address],
                    "action": actions[0],
                    "summary": summary,
                }
            )

    if kind == "create" and set(seen) != set(EXPECTED_TYPES):
        v.append("create plan must manage exactly the VM, its security group and its power state")
    if kind == "destroy":
        result.warnings.append(DATA_LOSS_WARNING)

    known = _prior_resource_ids(plan)
    orphans = sorted(r.resource_id for r in inventory if r.resource_id not in known)
    if orphans:
        v.append(
            "AWS has resources recorded or tagged for this deployment that are not in "
            "Terraform state "
            f"({', '.join(orphans)}); operator reconciliation is required"
        )
    if plan.get("resource_drift"):
        result.warnings.append(
            "Resources changed outside UnitCompute since the last apply; review carefully."
        )
    return result
