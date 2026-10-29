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

from unitcompute.provisioning.base import (
    TEMPLATE_VERSION,
    ApplyResult,
    DeploymentSpec,
    NetworkTargets,
    OwnedResource,
    PlanKind,
    PlanResult,
    ProvisioningError,
    RuntimeVersions,
    sha256_file,
    template_hash,
)
from unitcompute.provisioning.policy import AWS_PROVIDER, expected_tags

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


class SimulatedProvisioner:
    kind = "simulated"

    def __init__(self, data_dir: Path) -> None:
        self._state_dir = data_dir / "simulated-aws"
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

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
                "user_data": None,
                "launch_template": [],
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
                        "tags": {**tags, "Name": f"unitcompute-{spec.name}-root"},
                    }
                ],
                "tags": {**tags, "Name": f"unitcompute-{spec.name}"},
            },
        }

    def plan(
        self, spec: DeploymentSpec, kind: PlanKind, workdir: Path, frozen_ami_id: str | None
    ) -> PlanResult:
        ami_id = frozen_ami_id or SIMULATED_AMI
        workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
        current = self._load(spec.deployment_id)
        desired = self._desired(spec, ami_id)
        changes: list[dict[str, Any]] = []
        for address, values in desired.items():
            before = current.get(address)
            if kind == "destroy":
                if before is None:
                    continue
                actions, after = ["delete"], None
            elif before is None:
                actions, after = ["create"], {k: v for k, v in values.items() if k != "id"}
            else:
                actions, after = ["no-op"], before
            changes.append(
                {
                    "address": address,
                    "mode": "managed",
                    "type": address.split(".")[0],
                    "name": "vm",
                    "provider_name": AWS_PROVIDER,
                    "change": {"actions": actions, "before": before, "after": after},
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
                        {"address": "aws_instance.vm"},
                        {"address": "aws_security_group.vm"},
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
            }
        )

    def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
        state = self._load(deployment_id)
        found: list[OwnedResource] = []
        if "aws_instance.vm" in state:
            instance = state["aws_instance.vm"]
            found.append(OwnedResource("instance", instance["id"], "running"))
            found.append(
                OwnedResource("volume", instance["root_block_device"][0]["volume_id"], "in-use")
            )
        if "aws_security_group.vm" in state:
            found.append(
                OwnedResource("security_group", state["aws_security_group.vm"]["id"], "exists")
            )
        return found

    def ssm_ping_status(self, instance_id: str) -> str | None:
        return "Online (simulated)"
