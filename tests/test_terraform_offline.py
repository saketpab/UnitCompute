"""Runs the pinned Terraform binary offline against the reviewed template.

No AWS credentials are used: ``terraform test`` mocks the provider, and the plan test uses
a local-backend override with the provider's skip-validation flags. These prove the
template and policy agree with real Terraform output, not that AWS accepts the resources.
Set REQUIRE_TERRAFORM_TESTS=1 (as CI does) to fail instead of skip without the binary.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from test_policy import AMI, SPEC, TARGETS
from unitcompute.provisioning.base import template_dir
from unitcompute.provisioning.policy import evaluate_plan
from unitcompute.provisioning.terraform import PINNED_TERRAFORM_VERSION, build_tfvars, state_key

TERRAFORM = shutil.which("terraform") or str(Path.home() / ".local/bin/terraform")
pytestmark = pytest.mark.terraform

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


@pytest.fixture(scope="module")
def terraform_bin() -> str:
    if not Path(TERRAFORM).exists():
        if os.environ.get("REQUIRE_TERRAFORM_TESTS") == "1":
            pytest.fail("terraform binary required but not found")
        pytest.skip("terraform binary not installed")
    return TERRAFORM


def tf(binary: str, cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
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
    if check and result.returncode != 0:
        pytest.fail(f"terraform {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
    return result


@pytest.fixture(scope="module")
def module_copy(tmp_path_factory: pytest.TempPathFactory, terraform_bin: str) -> Path:
    workdir = tmp_path_factory.mktemp("module")
    shutil.copytree(template_dir(), workdir, dirs_exist_ok=True)
    tf(
        terraform_bin,
        workdir,
        "init",
        "-backend=false",
        "-input=false",
        "-lockfile=readonly",
        "-no-color",
    )
    return workdir


def test_pinned_version(terraform_bin: str, tmp_path: Path) -> None:
    out = json.loads(tf(terraform_bin, tmp_path, "version", "-json").stdout)
    assert out["terraform_version"] == PINNED_TERRAFORM_VERSION


def test_fmt_and_validate(terraform_bin: str, module_copy: Path) -> None:
    tf(terraform_bin, module_copy, "fmt", "-check", "-recursive", "-diff")
    assert "valid" in tf(terraform_bin, module_copy, "validate", "-no-color").stdout


def test_mocked_provider_module_tests(terraform_bin: str, module_copy: Path) -> None:
    out = tf(terraform_bin, module_copy, "test", "-no-color").stdout
    assert re.search(r"Success! \d+ passed, 0 failed", out), out


def _offline_plan(binary: str, source: Path, workdir: Path, kind: str = "create") -> dict[str, Any]:
    shutil.copytree(source, workdir, dirs_exist_ok=True)
    (workdir / "offline_override.tf").write_text(OFFLINE_OVERRIDE)
    (workdir / "vars.tfvars.json").write_text(json.dumps(build_tfvars(SPEC, TARGETS, AMI)))
    tf(binary, workdir, "init", "-input=false", "-lockfile=readonly", "-no-color")
    args = ["plan", "-input=false", "-no-color", "-var-file=vars.tfvars.json", "-out=tfplan"]
    if kind == "destroy":
        args.insert(1, "-destroy")
    tf(binary, workdir, *args)
    plan: dict[str, Any] = json.loads(tf(binary, workdir, "show", "-json", "tfplan").stdout)
    # Undo only what the offline override added to the provider block.
    plan["configuration"]["provider_config"]["aws"]["expressions"] = {
        "region": {"references": ["var.region"]},
        "allowed_account_ids": {"references": ["var.account_id"]},
    }
    return plan


def test_real_plan_passes_policy(terraform_bin: str, tmp_path: Path) -> None:
    plan = _offline_plan(terraform_bin, template_dir(), tmp_path / "plan")
    result = evaluate_plan(
        plan, kind="create", spec=SPEC, targets=TARGETS, ami_id=AMI, inventory=[]
    )
    assert result.violations == []


def test_real_empty_destroy_plan_passes_policy(terraform_bin: str, tmp_path: Path) -> None:
    plan = _offline_plan(terraform_bin, template_dir(), tmp_path / "destroy", "destroy")
    result = evaluate_plan(
        plan, kind="destroy", spec=SPEC, targets=TARGETS, ami_id=None, inventory=[]
    )
    assert result.violations == []
    assert result.changes == []


@pytest.mark.parametrize(
    "edit, expected",
    [
        (
            lambda s: s.replace(
                'http_tokens                 = "required"',
                'http_tokens                 = "optional"',
            ),
            "IMDSv2",
        ),
        (
            lambda s: s.replace(
                "  ingress = []",
                '  ingress = [{\n    description = "ssh"\n'
                '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n    ipv6_cidr_blocks = []\n'
                "    prefix_list_ids = []\n    security_groups = []\n"
                "    self = false\n  }]",
            ),
            "no inbound",
        ),
        (
            lambda s: s.replace(
                "  monitoring                  = false",
                '  monitoring                  = false\n  user_data = "#!/bin/sh"',
            ),
            "user data",
        ),
        (
            lambda s: s + '\nresource "aws_iam_user" "backdoor" {\n  name = "backdoor"\n}\n',
            "unexpected resource",
        ),
    ],
)
def test_tampered_template_is_rejected(
    terraform_bin: str, tmp_path: Path, edit: Any, expected: str
) -> None:
    source = tmp_path / "tampered-src"
    shutil.copytree(template_dir(), source)
    main = source / "main.tf"
    edited = edit(main.read_text())
    assert edited != main.read_text()
    main.write_text(edited)
    plan = _offline_plan(terraform_bin, source, tmp_path / "plan")
    violations = evaluate_plan(
        plan, kind="create", spec=SPEC, targets=TARGETS, ami_id=AMI, inventory=[]
    ).violations
    assert any(expected in v for v in violations), violations


def test_bootstrap_isolation() -> None:
    """The per-deployment template cannot reach bootstrap network, IAM or state."""
    text = "\n".join(p.read_text() for p in template_dir().glob("*.tf"))
    resources = re.findall(r'^resource "([^"]+)"', text, flags=re.MULTILINE)
    assert sorted(resources) == ["aws_instance", "aws_security_group"]
    assert not re.search(r'^\s*data "', text, flags=re.MULTILINE)
    assert "terraform_remote_state" not in text
    assert not re.search(r'^\s*module "', text, flags=re.MULTILINE)
    assert 'backend "s3" {}' in text  # partial config: key supplied per deployment
    assert state_key(SPEC.deployment_id) == f"deployments/{SPEC.deployment_id}/terraform.tfstate"
    lock = (template_dir() / ".terraform.lock.hcl").read_text()
    assert 'version     = "6.71.0"' in lock


def test_iam_examples_isolate_bootstrap_state() -> None:
    root = Path(__file__).parents[1] / "docs" / "iam"
    for name in ("plan-role-policy.json", "apply-role-policy.json"):
        policy = json.loads((root / name).read_text())
        text = json.dumps(policy)
        assert "bootstrap/" in text  # explicit deny on bootstrap state
        assert '"*"' not in json.dumps([s.get("Action") for s in policy["Statement"]])
        bucket = "arn:aws:s3:::${state_bucket}"
        allowed = [
            r
            for st in policy["Statement"]
            if st["Effect"] == "Allow"
            for r in ([st["Resource"]] if isinstance(st["Resource"], str) else st["Resource"])
            if r.startswith("arn:aws:s3:::")
        ]
        assert allowed and all(r in (bucket, f"{bucket}/deployments/*") for r in allowed)
