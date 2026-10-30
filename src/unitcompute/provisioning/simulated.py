"""Development-only simulated provisioner.

It never contacts AWS. It produces plan JSON in Terraform's shape so the API, worker,
policy and client examples can be exercised offline, and every result it produces is
labelled ``simulated``. It is rejected by configuration in production.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from unitcompute.durable import create_directory, ensure_directory
from unitcompute.provisioning.base import (
    TEMPLATE_VERSION,
    ApplyResult,
    DeploymentSpec,
    InstanceDetails,
    NetworkTargets,
    OwnedResource,
    PlanKind,
    PlanResult,
    ProvisioningError,
    Readiness,
    RuntimeVersions,
    check_dispatch,
    sha256_file,
    template_hash,
)
from unitcompute.provisioning.policy import (
    AWS_PROVIDER,
    CONFIGURED_ARGUMENTS,
    DEDICATED_GROUP_REFERENCES,
    INSTANCE_CREATE_VALUES,
    expected_tags,
)
from unitcompute.provisioning.state_evidence import PriorState

SIMULATED_AMI = "ami-0000000000000000a"
SIMULATED_TARGETS = NetworkTargets(
    account_id="000000000000",
    vpc_id="vpc-00000000000000000",
    subnet_id="subnet-00000000000000000",
    instance_profile_name="unitcompute-ssm-simulated",
)


def _sim_id(prefix: str, deployment_id: str) -> str:
    return f"{prefix}-{hashlib.sha256(deployment_id.encode()).hexdigest()[:17]}"


def _write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def simulated_lineage(deployment_id: str) -> str:
    return f"simulated-{deployment_id}"


def raw_state(
    lineage: str,
    serial: int,
    resources: dict[str, dict[str, Any]],
    terraform_version: str = "simulated",
) -> dict[str, Any]:
    """A raw (format 4) state document for ``address -> attributes``, with template outputs."""
    outputs: dict[str, Any] = {}
    instance = resources.get("aws_instance.vm")
    group = resources.get("aws_security_group.vm")
    if instance is not None:
        outputs["instance_id"] = {"value": instance["id"], "type": "string"}
        outputs["root_volume_id"] = {
            "value": instance["root_block_device"][0]["volume_id"],
            "type": "string",
        }
    if group is not None:
        outputs["security_group_id"] = {"value": group["id"], "type": "string"}
    return {
        "version": 4,
        "terraform_version": terraform_version,
        "serial": serial,
        "lineage": lineage,
        "outputs": outputs,
        "resources": [
            {
                "mode": "managed",
                "type": address.split(".")[0],
                "name": "vm",
                "provider": f'provider["{AWS_PROVIDER}"]',
                "instances": [{"schema_version": 1, "attributes": attributes}],
            }
            for address, attributes in resources.items()
        ],
        "check_results": None,
    }


def _keep_identity(before: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    """Desired values for an existing resource keep its IDs, as Terraform's state does."""
    kept = dict(desired)
    for key in ("id", "instance_id", "vpc_security_group_ids"):
        if key in before:
            kept[key] = before[key]
    if "root_block_device" in kept and before.get("root_block_device"):
        kept["root_block_device"] = [
            {**device, "volume_id": old.get("volume_id")}
            for device, old in zip(
                kept["root_block_device"], before["root_block_device"], strict=False
            )
        ]
    return kept


def _same(before: dict[str, Any], desired: dict[str, Any]) -> bool:
    """Whether the stored resource already matches the desired one (ignoring tags_all)."""
    return {k: v for k, v in before.items() if k != "tags_all"} == desired


def _expressions(address: str) -> dict[str, Any]:
    expressions: dict[str, Any] = {
        name: {"constant_value": "simulated"} for name in CONFIGURED_ARGUMENTS[address]
    }
    if address == "aws_instance.vm":
        expressions["vpc_security_group_ids"] = {"references": DEDICATED_GROUP_REFERENCES}
    return expressions


class SimulatedProvisioner:
    kind = "simulated"

    def __init__(self, data_dir: Path) -> None:
        self._state_dir = data_dir / "simulated-aws"
        ensure_directory(self._state_dir)

    def runtime_versions(self) -> RuntimeVersions:
        return RuntimeVersions(
            template_version=TEMPLATE_VERSION,
            template_hash=template_hash(),
            terraform_version="simulated",
            provider_versions={"registry.terraform.io/hashicorp/aws": "simulated"},
        )

    def network_targets(self) -> NetworkTargets:
        return SIMULATED_TARGETS

    def _state_path(self, deployment_id: str) -> Path:
        return self._state_dir / f"{deployment_id}.json"

    def _load(self, deployment_id: str) -> dict[str, dict[str, Any]]:
        path = self._state_path(deployment_id)
        if not path.exists():
            return {}
        data: dict[str, dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return data

    def _desired(self, spec: DeploymentSpec, ami_id: str) -> dict[str, dict[str, Any]]:
        tags = expected_tags(spec)
        t = SIMULATED_TARGETS
        return {
            "aws_security_group.vm": {
                "id": _sim_id("sg", spec.deployment_id),
                "name": f"unitcompute-{spec.deployment_id}",
                "description": "UnitCompute (simulated)",
                "revoke_rules_on_delete": False,
                "timeouts": None,
                "vpc_id": t.vpc_id,
                "region": spec.region,
                "ingress": [],
                "egress": [
                    {
                        "description": "HTTPS for SSM Agent and package repositories",
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                        "ipv6_cidr_blocks": [],
                        "prefix_list_ids": [],
                        "security_groups": [],
                        "self": False,
                    }
                ],
                "tags": {**tags, "Name": f"unitcompute-{spec.name}"},
            },
            "aws_instance.vm": {
                "id": _sim_id("i", spec.deployment_id),
                "ami": ami_id,
                "instance_type": spec.instance_type,
                "subnet_id": t.subnet_id,
                "region": spec.region,
                "iam_instance_profile": t.instance_profile_name,
                "associate_public_ip_address": True,
                "vpc_security_group_ids": [_sim_id("sg", spec.deployment_id)],
                **INSTANCE_CREATE_VALUES,
                "metadata_options": [
                    {
                        "http_endpoint": "enabled",
                        "http_tokens": "required",
                        "http_put_response_hop_limit": 1,
                    }
                ],
                "credit_specification": [{"cpu_credits": "standard"}],
                "root_block_device": [
                    {
                        "volume_id": _sim_id("vol", spec.deployment_id),
                        "volume_type": "gp3",
                        "volume_size": spec.disk_gib,
                        "encrypted": True,
                        "delete_on_termination": True,
                        "tags": None,
                    }
                ],
                "volume_tags": {**tags, "Name": f"unitcompute-{spec.name}-root"},
                "tags": {**tags, "Name": f"unitcompute-{spec.name}"},
            },
            "aws_ec2_instance_state.vm": {
                "id": _sim_id("i", spec.deployment_id),
                "instance_id": _sim_id("i", spec.deployment_id),
                "state": spec.power_state,
                "force": False,
                "region": spec.region,
                "timeouts": None,
            },
        }

    @staticmethod
    def _planned_create(
        values: dict[str, Any], current: dict[str, dict[str, Any]]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Mirror Terraform: computed IDs are unknown until apply."""
        after = {
            k: v
            for k, v in values.items()
            if k not in {"id", "vpc_security_group_ids", "instance_id"}
        }
        if "tags" in after:
            after["tags_all"] = after["tags"]
        unknown: dict[str, Any] = {"id": True}
        if "instance_id" in values:
            unknown["instance_id"] = True
        if "root_block_device" in after:
            after["root_block_device"] = [
                {k: v for k, v in device.items() if k != "volume_id"}
                for device in after["root_block_device"]
            ]
            group = current.get("aws_security_group.vm")
            if group is None:
                unknown["vpc_security_group_ids"] = True
            else:
                after["vpc_security_group_ids"] = [group["id"]]
        return after, unknown

    def plan(
        self, spec: DeploymentSpec, kind: PlanKind, workdir: Path, frozen_ami_id: str | None
    ) -> PlanResult:
        ami_id = frozen_ami_id or SIMULATED_AMI
        create_directory(workdir)
        current = self._load(spec.deployment_id)
        desired = self._desired(spec, ami_id)
        for address, before_values in current.items():
            if address in desired:  # an edit never changes what a resource is
                desired[address] = _keep_identity(before_values, desired[address])
        changes: list[dict[str, Any]] = []
        for address, values in desired.items():
            before = current.get(address)
            if kind == "destroy":
                if before is None:
                    continue
                actions, after = ["delete"], None
            elif before is None:
                actions = ["create"]
                after, unknown = self._planned_create(values, current)
            elif _same(before, values):
                actions, after = ["no-op"], before
            else:  # edit in place: new name (tags), larger disk, or power state
                actions = ["update"]
                after = {**values, "tags_all": values["tags"]} if "tags" in values else values
            changes.append(
                {
                    "address": address,
                    "mode": "managed",
                    "type": address.split(".")[0],
                    "name": "vm",
                    "provider_name": AWS_PROVIDER,
                    "change": {
                        "actions": actions,
                        "before": before,
                        "after": after,
                        "after_unknown": unknown if actions == ["create"] else {},
                    },
                }
            )
        t = SIMULATED_TARGETS
        variables = {
            "region": spec.region,
            "account_id": t.account_id,
            "deployment_id": spec.deployment_id,
            "owner_tag": spec.owner_tag,
            "name": spec.name,
            "disk_gib": spec.disk_gib,
            "instance_type": spec.instance_type,
            "power_state": spec.power_state,
            "ami_id": ami_id,
            "vpc_id": t.vpc_id,
            "subnet_id": t.subnet_id,
            "instance_profile_name": t.instance_profile_name,
        }
        plan_json: dict[str, Any] = {
            "format_version": "1.2",
            "terraform_version": "simulated",
            "errored": False,
            "complete": True,
            "variables": {k: {"value": v} for k, v in variables.items()},
            "resource_changes": changes,
            "configuration": {
                "provider_config": {
                    "aws": {
                        "name": "aws",
                        "full_name": AWS_PROVIDER,
                        "expressions": {
                            "region": {"references": ["var.region"]},
                            "allowed_account_ids": {"references": ["var.account_id"]},
                        },
                    }
                },
                "root_module": {
                    "resources": [
                        {
                            "address": address,
                            "mode": "managed",
                            "type": address.split(".")[0],
                            "name": "vm",
                            "provider_config_key": "aws",
                            "expressions": _expressions(address),
                        }
                        for address in CONFIGURED_ARGUMENTS
                    ]
                },
            },
            "prior_state": {
                "values": {
                    "root_module": {
                        "resources": [{"address": a, "values": v} for a, v in current.items()]
                    }
                }
            },
        }
        plan_path = workdir / "tfplan"
        intent = {
            "simulated": True,
            "kind": kind,
            "deployment_id": spec.deployment_id,
            "desired": desired,
            "plan": plan_json,
        }
        _write_private(plan_path, json.dumps(intent, sort_keys=True).encode(), 0o400)
        return PlanResult(
            plan_path=plan_path,
            plan_hash=sha256_file(plan_path),
            plan_json=plan_json,
            account_id=t.account_id,
            ami_id=ami_id,
            versions=self.runtime_versions(),
        )

    def apply(self, spec: DeploymentSpec, workdir: Path, plan_path: Path) -> ApplyResult:
        check_dispatch()
        intent = json.loads(plan_path.read_bytes())
        if intent.get("deployment_id") != spec.deployment_id or not intent.get("simulated"):
            raise ProvisioningError("plan_invalid", "Simulated plan does not match deployment.")
        state_path = self._state_path(spec.deployment_id)
        if intent["kind"] == "destroy":
            state_path.unlink(missing_ok=True)
            return ApplyResult()
        desired = intent["desired"]
        _write_private(state_path, json.dumps(desired, sort_keys=True).encode())
        instance = desired["aws_instance.vm"]
        return ApplyResult(
            outputs={
                "instance_id": instance["id"],
                "security_group_id": desired["aws_security_group.vm"]["id"],
                "root_volume_id": instance["root_block_device"][0]["volume_id"],
                "power_state": desired["aws_ec2_instance_state.vm"]["state"],
            }
        )

    def capture_stored_state(self, spec: DeploymentSpec, workdir: Path) -> object:
        state = self._load(spec.deployment_id)
        return raw_state(simulated_lineage(spec.deployment_id), 1 if state else 0, state)

    def prior_state(self, plan_path: Path) -> PriorState:
        intent = json.loads(plan_path.read_bytes())
        return PriorState(simulated_lineage(str(intent.get("deployment_id"))), 0)

    def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
        state = self._load(deployment_id)
        found: list[OwnedResource] = []
        if "aws_instance.vm" in state:
            instance = state["aws_instance.vm"]
            power = state.get("aws_ec2_instance_state.vm", {}).get("state", "running")
            found.append(OwnedResource("instance", instance["id"], power))
            found.append(
                OwnedResource("volume", instance["root_block_device"][0]["volume_id"], "in-use")
            )
        if "aws_security_group.vm" in state:
            found.append(
                OwnedResource("security_group", state["aws_security_group.vm"]["id"], "exists")
            )
        return found

    def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
        wanted = set(resource_ids)
        found: list[OwnedResource] = []
        for path in sorted(self._state_dir.glob("dep_*.json")):
            for resource in self.owned_resources(path.stem):
                if resource.resource_id in wanted:
                    found.append(resource)
        return found

    def instance_volumes(self, instance_ids: list[str]) -> dict[str, list[tuple[str, bool]]]:
        wanted = set(instance_ids)
        volumes: dict[str, list[tuple[str, bool]]] = {}
        for path in sorted(self._state_dir.glob("dep_*.json")):
            instance = self._load(path.stem).get("aws_instance.vm")
            if instance and instance["id"] in wanted:
                volumes[instance["id"]] = [(instance["root_block_device"][0]["volume_id"], True)]
        return volumes

    def managed_resources(self) -> list[tuple[OwnedResource, str | None]]:
        found: list[tuple[OwnedResource, str | None]] = []
        for path in sorted(self._state_dir.glob("dep_*.json")):
            found.extend((r, path.stem) for r in self.owned_resources(path.stem))
        return found

    def instance_details(self, instance_ids: list[str]) -> dict[str, InstanceDetails]:
        wanted = set(instance_ids)
        details: dict[str, InstanceDetails] = {}
        for path in sorted(self._state_dir.glob("dep_*.json")):
            state = self._load(path.stem)
            instance = state.get("aws_instance.vm")
            if instance and instance["id"] in wanted:
                root = instance["root_block_device"][0]
                details[instance["id"]] = InstanceDetails(
                    state=state.get("aws_ec2_instance_state.vm", {}).get("state", "running"),
                    root_volume_id=root["volume_id"],
                    root_volume_gib=root["volume_size"],
                )
        return details

    def connection_readiness(self, instance_id: str) -> Readiness:
        state = self.instance_details([instance_id]).get(instance_id)
        if state is not None and state.state != "running":
            return Readiness(ec2_status=None, ssm_status=None, instance_state=state.state)
        return Readiness(ec2_status="ok", ssm_status="Online (simulated)", instance_state="running")

    def self_check(self) -> dict[str, Any]:
        return {"provisioner": "simulated", "aws": "not contacted"}
