"""Subprocess safety of the Terraform runner and the exact commands the provisioner issues."""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from conftest import FAKE_AWS_KEY_ID, make_settings
from unitcompute.provisioning.aws import TemporaryCredentials
from unitcompute.provisioning.base import DeploymentSpec, ProvisioningError, ProvisioningTimeout
from unitcompute.provisioning.runner import RunResult, TerraformRunner
from unitcompute.provisioning.terraform import TFVARS_FILE, TerraformProvisioner

FAKE_TF = f"""#!/bin/sh
# Records argv (one per line) and environment, then behaves per FAKE_MODE file.
printf '%s\\n' "$@" > "$PWD/argv.txt"
env > "$PWD/env.txt"
mode=$(cat "$(dirname "$0")/mode" 2>/dev/null)
case "$mode" in
  sleep) sleep 30 ;;
  fail) echo "Error: {FAKE_AWS_KEY_ID} leaked secret_access_key=abc123secretvalue" >&2; exit 1 ;;
esac
echo '{{"terraform_version":"1.17.1"}}'
"""


@pytest.fixture
def fake_tf(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = bindir / "terraform"
    binary.write_text(FAKE_TF)
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def _workdir(tmp_path: Path) -> Path:
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)
    return workdir


def test_arguments_are_not_shell_interpreted(tmp_path: Path, fake_tf: Path) -> None:
    runner = TerraformRunner(fake_tf)
    workdir = _workdir(tmp_path)
    hostile = "-var=name=x; touch PWNED $(touch PWNED2) `touch PWNED3`"
    runner.run(
        ["plan", hostile],
        workdir=workdir,
        env=runner.base_env(workdir),
        timeout=10,
        log_name="plan",
    )
    assert (workdir / "argv.txt").read_text().splitlines() == ["plan", hostile]
    assert not any((workdir / name).exists() for name in ("PWNED", "PWNED2", "PWNED3"))


def test_environment_is_controlled(
    tmp_path: Path, fake_tf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UNRELATED_SECRET", "should-not-leak")
    monkeypatch.setenv("TF_LOG", "TRACE")
    runner = TerraformRunner(fake_tf, plugin_cache_dir=tmp_path / "cache")
    workdir = _workdir(tmp_path)
    runner.run(
        ["version"], workdir=workdir, env=runner.base_env(workdir), timeout=10, log_name="version"
    )
    env = dict(
        line.split("=", 1) for line in (workdir / "env.txt").read_text().splitlines() if "=" in line
    )
    assert "UNRELATED_SECRET" not in env and "TF_LOG" not in env
    assert env["TF_INPUT"] == "0" and env["TF_IN_AUTOMATION"] == "1"
    assert env["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"


def test_disallowed_subcommands(tmp_path: Path, fake_tf: Path) -> None:
    runner = TerraformRunner(fake_tf)
    workdir = _workdir(tmp_path)
    for args in (
        ["destroy"],
        ["state", "rm", "x"],
        ["state", "push", "errored.tfstate"],
        ["state", "pull", "extra"],
        ["state"],
        ["force-unlock", "id"],
        ["import"],
        ["console"],
        [],
    ):
        with pytest.raises(ValueError, match="not allowed"):
            runner.run(args, workdir=workdir, env={}, timeout=5, log_name="x")


def test_timeout_kills_process_group(tmp_path: Path, fake_tf: Path) -> None:
    (fake_tf.parent / "mode").write_text("sleep")
    runner = TerraformRunner(fake_tf)
    workdir = _workdir(tmp_path)
    started = time.monotonic()
    with pytest.raises(ProvisioningTimeout):
        runner.run(
            ["apply", "tfplan"],
            workdir=workdir,
            env=runner.base_env(workdir),
            timeout=1,
            log_name="apply",
        )
    assert time.monotonic() - started < 15


def test_logs_are_redacted_and_private(tmp_path: Path, fake_tf: Path) -> None:
    (fake_tf.parent / "mode").write_text("fail")
    runner = TerraformRunner(fake_tf)
    workdir = _workdir(tmp_path)
    result = runner.run(
        ["plan"],
        workdir=workdir,
        env=runner.base_env(workdir),
        timeout=10,
        log_name="plan",
        secrets=["abc123secretvalue"],
    )
    assert result.returncode == 1
    log = workdir / "logs" / "plan.log"
    text = log.read_text()
    assert FAKE_AWS_KEY_ID not in text and "abc123secretvalue" not in text
    assert "AKIA" not in result.stderr
    assert log.stat().st_mode & 0o077 == 0


# ------------------------------------------------------------------- provisioner commands


class RecordingRunner(TerraformRunner):
    def __init__(self) -> None:
        super().__init__(Path("/nonexistent/terraform"))
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def run(
        self,
        args: Any,
        *,
        workdir: Path,
        env: Any,
        timeout: float,
        log_name: str,
        secrets: Any = (),
    ) -> RunResult:
        self.calls.append((list(args), dict(env)))
        if args[0] == "version":
            return RunResult(0, json.dumps({"terraform_version": "1.17.1"}), "")
        if args[0] == "plan":
            out = Path(workdir) / "tfplan"
            out.write_bytes(b"binary-plan")
        if args[0] == "show":
            return RunResult(0, json.dumps({"errored": False}), "")
        if args[0] == "output":
            return RunResult(0, json.dumps({"instance_id": {"value": "i-0abc"}}), "")
        return RunResult(0, "", "")


class FakeAws:
    creds = TemporaryCredentials("ASIA" + "FAKEFAKEFAKEFAKE", "secret-value-123", "token-value-456")

    def __init__(self) -> None:
        self.roles: list[str] = []
        self.scopes: list[str | None] = []

    def credentials(
        self, role: str, session_name: str, deployment_id: str | None = None
    ) -> TemporaryCredentials:
        self.roles.append(role)
        self.scopes.append(deployment_id)
        return self.creds

    def account_id(self, creds: TemporaryCredentials) -> str:
        return "123456789012"

    def resolve_ami(self, creds: TemporaryCredentials) -> str:
        return "ami-0123456789abcdef0"

    def verify_role_identity(self, role: str) -> dict[str, str]:
        return {"account": "****9012", "role": f"unitcompute-{role}"}

    def owned_resources(self, deployment_id: str, creds: TemporaryCredentials) -> list[Any]:
        return []

    def find_resources(self, ids: list[str], creds: TemporaryCredentials) -> list[Any]:
        return []

    def instance_volumes(self, ids: list[str], creds: TemporaryCredentials) -> dict[str, Any]:
        return {}


SPEC = DeploymentSpec(
    "dep_0123456789abcdef0123456789abcdef", "0123456789abcdef", "demo", 8, "us-east-1", "t3.micro"
)


def _provisioner(tmp_path: Path) -> tuple[TerraformProvisioner, RecordingRunner, FakeAws]:
    from test_config_and_auth import TERRAFORM_SETTINGS

    settings = make_settings(tmp_path, **TERRAFORM_SETTINGS)
    runner, aws = RecordingRunner(), FakeAws()
    return TerraformProvisioner(settings, runner, aws), runner, aws  # type: ignore[arg-type]


def test_plan_commands_and_backend(tmp_path: Path) -> None:
    provisioner, runner, aws = _provisioner(tmp_path)
    workdir = tmp_path / "data" / "work" / SPEC.deployment_id / "plan_x"
    result = provisioner.plan(SPEC, "create", workdir, None)
    commands = [args for args, _ in runner.calls]
    assert commands[0] == ["version", "-json"]
    assert commands[1] == [
        "init",
        "-input=false",
        "-no-color",
        "-lockfile=readonly",
        "-backend-config=bucket=unitcompute-state-example",
        f"-backend-config=key=deployments/{SPEC.deployment_id}/terraform.tfstate",
        "-backend-config=region=us-east-1",
        "-backend-config=encrypt=true",
        "-backend-config=use_lockfile=true",
    ]
    assert commands[2] == [
        "plan",
        "-input=false",
        "-no-color",
        "-lock-timeout=60s",
        f"-var-file={TFVARS_FILE}",
        "-out=tfplan",
    ]
    assert commands[3] == ["show", "-json", "-no-color", "tfplan"]
    assert aws.roles == ["plan"]
    assert result.ami_id == "ami-0123456789abcdef0"
    assert workdir.stat().st_mode & 0o077 == 0
    tfvars = json.loads((workdir / TFVARS_FILE).read_text())
    assert tfvars == {
        "region": "us-east-1",
        "account_id": "123456789012",
        "deployment_id": SPEC.deployment_id,
        "owner_tag": SPEC.owner_tag,
        "name": "demo",
        "disk_gib": 8,
        "instance_type": "t3.micro",
        "power_state": "running",
        "ami_id": "ami-0123456789abcdef0",
        "vpc_id": "vpc-0123456789abcdef0",
        "subnet_id": "subnet-0123456789abcdef0",
        "instance_profile_name": "unitcompute-ssm",
    }
    copied = sorted(p.name for p in workdir.iterdir() if p.suffix in {".tf", ".hcl"})
    assert copied == [".terraform.lock.hcl", "main.tf", "outputs.tf", "variables.tf", "versions.tf"]
    _, env = runner.calls[2]
    assert env["AWS_SESSION_TOKEN"] == "token-value-456"


def test_destroy_plan_and_apply_use_exact_saved_plan(tmp_path: Path) -> None:
    provisioner, runner, aws = _provisioner(tmp_path)
    workdir = tmp_path / "data" / "work" / SPEC.deployment_id / "plan_y"
    provisioner.plan(SPEC, "destroy", workdir, "ami-0123456789abcdef0")
    assert runner.calls[2][0][:2] == ["plan", "-destroy"]
    runner.calls.clear()
    outcome = provisioner.apply(SPEC, workdir, workdir / "tfplan")
    assert runner.calls[0][0] == [
        "apply",
        "-input=false",
        "-no-color",
        "-lock-timeout=60s",
        "tfplan",
    ]
    assert aws.roles[-1] == "apply"
    assert outcome.outputs == {"instance_id": "i-0abc"}
    with pytest.raises(ProvisioningError):
        provisioner.apply(SPEC, workdir, tmp_path / "elsewhere" / "tfplan")


def test_frozen_ami_is_reused(tmp_path: Path) -> None:
    provisioner, _, _ = _provisioner(tmp_path)
    workdir = tmp_path / "data" / "work" / SPEC.deployment_id / "plan_z"
    result = provisioner.plan(SPEC, "create", workdir, "ami-0aaaaaaaaaaaaaaa0")
    assert result.ami_id == "ami-0aaaaaaaaaaaaaaa0"


def test_terraform_version_mismatch(tmp_path: Path) -> None:
    provisioner, runner, _ = _provisioner(tmp_path)

    def wrong_version(args: Any, **kwargs: Any) -> RunResult:
        return RunResult(0, json.dumps({"terraform_version": "1.5.0"}), "")

    runner.run = wrong_version  # type: ignore[method-assign]
    with pytest.raises(ProvisioningError, match=r"1\.17\.1"):
        provisioner.runtime_versions()


def test_workdir_is_never_reused(tmp_path: Path) -> None:
    provisioner, _, _ = _provisioner(tmp_path)
    workdir = tmp_path / "data" / "work" / SPEC.deployment_id / "plan_w"
    provisioner.plan(SPEC, "create", workdir, None)
    with pytest.raises(FileExistsError):
        provisioner.plan(SPEC, "create", workdir, None)


def test_credentials_repr_is_redacted() -> None:
    assert "secret" not in repr(FakeAws.creds)
