"""Real offline Terraform plans for the policy tests (no AWS, no credentials).

``create_plan`` plans the reviewed template from nothing. ``update_plan`` plans an *edit* of an
existing VM: it builds a prior state from that create plan with synthetic IDs, as if the VM had
been applied, and plans the changed variables against it with ``-refresh=false`` (a refresh
would call AWS). The result is genuine ``terraform show -json`` output for an in-place update,
not a hand-written approximation of one. Run this module to regenerate the static fixtures:

    uv run python tests/make_fixtures.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from unitcompute.provisioning.base import DeploymentSpec, NetworkTargets, template_dir
from unitcompute.provisioning.terraform import build_tfvars

OFFLINE_OVERRIDE = """
terraform {
  backend "local" {}
}
provider "aws" {
  access_key                  = "offline-test"
  secret_key                  = "offline-test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  allowed_account_ids         = null
}
"""

FAKE_INSTANCE = "i-0aaaaaaaaaaaaaaa1"
FAKE_GROUP = "sg-0aaaaaaaaaaaaaaa1"
FAKE_VOLUME = "vol-0aaaaaaaaaaaaaaa1"
PRODUCTION_PROVIDER_EXPRESSIONS = {
    "region": {"references": ["var.region"]},
    "allowed_account_ids": {"references": ["var.account_id"]},
}


def tf(binary: str, cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(cwd),
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    }
    cache = os.environ.get("TF_PLUGIN_CACHE_DIR")
    if cache:
        env["TF_PLUGIN_CACHE_DIR"] = cache
    result = subprocess.run(
        [binary, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"terraform {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def _prepare(source: Path, workdir: Path, binary: str) -> None:
    shutil.copytree(source, workdir, dirs_exist_ok=True)
    (workdir / "offline_override.tf").write_text(OFFLINE_OVERRIDE)
    tf(binary, workdir, "init", "-input=false", "-lockfile=readonly", "-no-color")


def _show(binary: str, workdir: Path) -> dict[str, Any]:
    plan: dict[str, Any] = json.loads(tf(binary, workdir, "show", "-json", "tfplan").stdout)
    # Undo only what the offline override added to the provider block.
    plan["configuration"]["provider_config"]["aws"]["expressions"] = PRODUCTION_PROVIDER_EXPRESSIONS
    plan.pop("timestamp", None)  # Terraform's own non-deterministic fields
    if isinstance(plan.get("relevant_attributes"), list):
        plan["relevant_attributes"].sort(key=lambda item: json.dumps(item, sort_keys=True))
    return plan


def create_plan(
    binary: str,
    source: Path,
    workdir: Path,
    spec: DeploymentSpec,
    targets: NetworkTargets,
    ami_id: str,
    *,
    destroy: bool = False,
) -> dict[str, Any]:
    _prepare(source, workdir, binary)
    (workdir / "vars.tfvars.json").write_text(json.dumps(build_tfvars(spec, targets, ami_id)))
    args = ["plan", "-input=false", "-no-color", "-var-file=vars.tfvars.json", "-out=tfplan"]
    if destroy:
        args.insert(1, "-destroy")
    tf(binary, workdir, *args)
    return _show(binary, workdir)


def _fill(after: dict[str, Any], unknown: dict[str, Any], fakes: dict[str, Any]) -> dict[str, Any]:
    out = dict(after)
    for key, flag in unknown.items():
        if flag is True:
            out[key] = fakes.get(key)
        elif isinstance(flag, list) and isinstance(out.get(key), list):
            out[key] = [
                _fill(
                    a,
                    b,
                    {
                        "volume_id": FAKE_VOLUME,
                        "device_name": "/dev/xvda",
                        "iops": 3000,
                        "throughput": 125,
                        "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/fake",
                        "tags": {},
                        "tags_all": {},
                    },
                )
                if isinstance(a, dict) and isinstance(b, dict)
                else a
                for a, b in zip(out[key], flag, strict=False)
            ]
    return out


def synthetic_state(created: dict[str, Any]) -> dict[str, Any]:
    """A Terraform v4 state as if ``created`` (a create plan) had been applied."""
    fakes: dict[str, dict[str, Any]] = {
        "aws_instance.vm": {
            "id": FAKE_INSTANCE,
            "arn": f"arn:aws:ec2:us-east-1:123456789012:instance/{FAKE_INSTANCE}",
            "vpc_security_group_ids": [FAKE_GROUP],
            "security_groups": [],
            "tenancy": "default",
            "instance_state": "running",
        },
        "aws_security_group.vm": {
            "id": FAKE_GROUP,
            "arn": f"arn:aws:ec2:us-east-1:123456789012:security-group/{FAKE_GROUP}",
            "owner_id": "123456789012",
        },
        "aws_ec2_instance_state.vm": {"id": FAKE_INSTANCE, "instance_id": FAKE_INSTANCE},
    }
    resources = []
    for change in created["resource_changes"]:
        body = change["change"]
        attributes = _fill(body["after"], body["after_unknown"], fakes[change["address"]])
        attributes.update(fakes[change["address"]])
        for device in attributes.get("root_block_device") or []:
            if isinstance(device, dict) and device.get("tags") is None:
                device["tags"] = {}  # how the provider reads a root volume back
        resources.append(
            {
                "mode": "managed",
                "type": change["type"],
                "name": "vm",
                "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [
                    {
                        "schema_version": 1 if change["type"] != "aws_ec2_instance_state" else 0,
                        "attributes": attributes,
                    }
                ],
            }
        )
    return {
        "version": 4,
        "terraform_version": "1.17.1",
        "serial": 1,
        "lineage": "00000000-0000-0000-0000-000000000000",
        "outputs": {},
        "resources": resources,
    }


def update_plan(
    binary: str,
    source: Path,
    workdir: Path,
    before: DeploymentSpec,
    after: DeploymentSpec,
    targets: NetworkTargets,
    ami_id: str,
) -> dict[str, Any]:
    """The plan for editing ``before`` into ``after`` (name, larger disk, power state)."""
    _prepare(source, workdir, binary)
    (workdir / "vars.tfvars.json").write_text(json.dumps(build_tfvars(before, targets, ami_id)))
    tf(
        binary,
        workdir,
        "plan",
        "-input=false",
        "-no-color",
        "-var-file=vars.tfvars.json",
        "-out=create.tfplan",
    )
    created: dict[str, Any] = json.loads(
        tf(binary, workdir, "show", "-json", "create.tfplan").stdout
    )
    (workdir / "terraform.tfstate").write_text(json.dumps(synthetic_state(created)))
    (workdir / "vars.tfvars.json").write_text(json.dumps(build_tfvars(after, targets, ami_id)))
    tf(
        binary,
        workdir,
        "plan",
        "-input=false",
        "-no-color",
        "-refresh=false",
        "-var-file=vars.tfvars.json",
        "-out=tfplan",
    )
    return _show(binary, workdir)


def default_template() -> Path:
    return template_dir()
