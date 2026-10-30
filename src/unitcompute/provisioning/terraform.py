"""Terraform-backed provisioner: saved plans, exact-plan apply, per-deployment S3 state."""

from __future__ import annotations

import json
import os
import shutil
from functools import cached_property
from pathlib import Path
from typing import Any

from unitcompute.config import Settings
from unitcompute.durable import create_directory, ensure_directory
from unitcompute.provisioning.aws import (
    AwsEnvironment,
    TemporaryCredentials,
    packed_session_policy,
)
from unitcompute.provisioning.base import (
    TEMPLATE_VERSION,
    ApplyResult,
    DeploymentSpec,
    NetworkTargets,
    OwnedResource,
    PlanKind,
    PlanResult,
    ProvisioningError,
    Readiness,
    RuntimeVersions,
    check_dispatch,
    lock_provider_versions,
    sha256_file,
    template_dir,
    template_hash,
)
from unitcompute.provisioning.runner import RunResult, TerraformRunner
from unitcompute.provisioning.state_evidence import (
    PriorState,
    StateEvidenceError,
    load_state_bytes,
    prior_state_from_planfile,
)

PINNED_TERRAFORM_VERSION = "1.17.1"
PLAN_FILE = "tfplan"
TFVARS_FILE = "unitcompute.tfvars.json"


def state_key(deployment_id: str) -> str:
    return f"deployments/{deployment_id}/terraform.tfstate"


def prepare_workdir(workdir: Path, tfvars: dict[str, Any], source: Path | None = None) -> None:
    """Copy the reviewed template into a fresh private directory with validated tfvars."""
    source = source or template_dir()
    create_directory(workdir)
    for path in sorted(source.iterdir()):
        if path.is_file() and (path.suffix == ".tf" or path.name == ".terraform.lock.hcl"):
            shutil.copyfile(path, workdir / path.name)
            os.chmod(workdir / path.name, 0o600)
    fd = os.open(workdir / TFVARS_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(tfvars, handle, sort_keys=True)


def build_tfvars(spec: DeploymentSpec, targets: NetworkTargets, ami_id: str) -> dict[str, Any]:
    return {
        "region": spec.region,
        "account_id": targets.account_id,
        "deployment_id": spec.deployment_id,
        "owner_tag": spec.owner_tag,
        "name": spec.name,
        "disk_gib": spec.disk_gib,
        "instance_type": spec.instance_type,
        "ami_id": ami_id,
        "vpc_id": targets.vpc_id,
        "subnet_id": targets.subnet_id,
        "instance_profile_name": targets.instance_profile_name,
    }


class TerraformProvisioner:
    kind = "terraform"

    def __init__(self, settings: Settings, runner: TerraformRunner, aws: AwsEnvironment) -> None:
        self._settings = settings
        self._runner = runner
        self._aws = aws

    def network_targets(self) -> NetworkTargets:
        s = self._settings
        if not (s.aws_account_id and s.vpc_id and s.subnet_id and s.instance_profile_name):
            raise ProvisioningError("aws_not_configured", "AWS network targets are not set.")
        return NetworkTargets(
            account_id=s.aws_account_id,
            vpc_id=s.vpc_id,
            subnet_id=s.subnet_id,
            instance_profile_name=s.instance_profile_name,
        )

    @cached_property
    def _versions(self) -> RuntimeVersions:
        scratch = self._settings.workdir_root / "_version"
        ensure_directory(scratch)
        result = self._runner.run(
            ["version", "-json"],
            workdir=scratch,
            env=self._runner.base_env(scratch),
            timeout=30,
            log_name="version",
        )
        try:
            version = str(json.loads(result.stdout)["terraform_version"])
        except (ValueError, KeyError) as exc:
            raise ProvisioningError("terraform_unavailable", "Terraform is not usable.") from exc
        if version != PINNED_TERRAFORM_VERSION:
            raise ProvisioningError(
                "terraform_version_mismatch",
                f"Terraform {PINNED_TERRAFORM_VERSION} is required (found {version}).",
            )
        return RuntimeVersions(
            template_version=TEMPLATE_VERSION,
            template_hash=template_hash(),
            terraform_version=version,
            provider_versions=lock_provider_versions(),
        )

    def runtime_versions(self) -> RuntimeVersions:
        return self._versions

    def _env(self, workdir: Path, creds: TemporaryCredentials) -> dict[str, str]:
        return {**self._runner.base_env(workdir), **creds.env(self._settings.aws_region)}

    def _run(
        self,
        args: list[str],
        workdir: Path,
        creds: TemporaryCredentials,
        timeout: float,
        log_name: str,
        error_code: str,
        mutating: bool = False,
    ) -> RunResult:
        env = self._env(workdir, creds)
        if mutating:
            # The last point at which the approved plan can still be refused: after the
            # credential exchange and every other preparation, immediately before the spawn.
            check_dispatch()
        result = self._runner.run(
            args,
            workdir=workdir,
            env=env,
            timeout=timeout,
            log_name=log_name,
            secrets=creds.secrets(),
        )
        if result.returncode < 0:
            # Killed by a signal: whatever Terraform had done was not reported or persisted
            # as a final state.
            raise ProvisioningError(
                "terraform_signalled",
                f"terraform {args[0]} was terminated by a signal; its outcome is unknown.",
            )
        if result.returncode != 0:
            raise ProvisioningError(error_code, f"terraform {args[0]} failed; see the job log.")
        return result

    def plan(
        self, spec: DeploymentSpec, kind: PlanKind, workdir: Path, frozen_ami_id: str | None
    ) -> PlanResult:
        versions = self.runtime_versions()
        creds = self._aws.credentials(
            "plan", f"uc-plan-{spec.deployment_id[4:20]}", spec.deployment_id
        )
        account_id = self._aws.account_id(creds)
        ami_id = frozen_ami_id or self._aws.resolve_ami(creds)
        prepare_workdir(workdir, build_tfvars(spec, self.network_targets(), ami_id))
        timeout = self._settings.plan_timeout_seconds
        bucket = self._settings.state_bucket
        self._run(
            [
                "init",
                "-input=false",
                "-no-color",
                "-lockfile=readonly",
                f"-backend-config=bucket={bucket}",
                f"-backend-config=key={state_key(spec.deployment_id)}",
                f"-backend-config=region={self._settings.aws_region}",
                "-backend-config=encrypt=true",
                "-backend-config=use_lockfile=true",
            ],
            workdir,
            creds,
            timeout,
            "init",
            "terraform_init_failed",
        )
        plan_args = [
            "plan",
            "-input=false",
            "-no-color",
            "-lock-timeout=60s",
            f"-var-file={TFVARS_FILE}",
            f"-out={PLAN_FILE}",
        ]
        if kind == "destroy":
            plan_args.insert(1, "-destroy")
        self._run(plan_args, workdir, creds, timeout, "plan", "terraform_plan_failed")
        plan_path = workdir / PLAN_FILE
        os.chmod(plan_path, 0o400)
        shown = self._run(
            ["show", "-json", "-no-color", PLAN_FILE],
            workdir,
            creds,
            timeout,
            "show",
            "terraform_show_failed",
        )
        try:
            plan_json = json.loads(shown.stdout)
        except ValueError as exc:
            raise ProvisioningError("terraform_show_failed", "Plan JSON was unreadable.") from exc
        return PlanResult(
            plan_path=plan_path,
            plan_hash=sha256_file(plan_path),
            plan_json=plan_json,
            account_id=account_id,
            ami_id=ami_id,
            versions=versions,
        )

    def apply(self, spec: DeploymentSpec, workdir: Path, plan_path: Path) -> ApplyResult:
        if plan_path != workdir / PLAN_FILE:
            raise ProvisioningError("plan_path_invalid", "Plan file is not in its work directory.")
        creds = self._aws.credentials(
            "apply", f"uc-apply-{spec.deployment_id[4:20]}", spec.deployment_id
        )
        timeout = self._settings.apply_timeout_seconds
        self._run(
            ["apply", "-input=false", "-no-color", "-lock-timeout=60s", PLAN_FILE],
            workdir,
            creds,
            timeout,
            "apply",
            "terraform_apply_failed",
            mutating=True,
        )
        shown = self._run(
            ["output", "-json", "-no-color"],
            workdir,
            creds,
            120,
            "output",
            "terraform_output_failed",
        )
        try:
            raw = json.loads(shown.stdout)
        except ValueError:
            raw = {}
        outputs = {
            key: str(value.get("value"))
            for key, value in raw.items()
            if isinstance(value, dict) and isinstance(value.get("value"), str)
        }
        return ApplyResult(outputs=outputs)

    def capture_stored_state(self, spec: DeploymentSpec, workdir: Path) -> object:
        creds = self._aws.credentials(
            "plan", f"uc-capture-{spec.deployment_id[4:20]}", spec.deployment_id
        )
        pulled = self._run(
            ["state", "pull"],
            workdir,
            creds,
            300,
            "state-pull",
            "state_capture_failed",
        )
        try:
            return load_state_bytes(pulled.stdout.encode())
        except StateEvidenceError as exc:
            raise ProvisioningError("state_capture_failed", "Stored state was unreadable.") from exc

    def prior_state(self, plan_path: Path) -> PriorState:
        return prior_state_from_planfile(plan_path)

    def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
        creds = self._aws.credentials("plan", f"uc-inventory-{deployment_id[4:20]}")
        return self._aws.owned_resources(deployment_id, creds)

    def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
        creds = self._aws.credentials("plan", "uc-verify-ids")
        return self._aws.find_resources(resource_ids, creds)

    def instance_volumes(self, instance_ids: list[str]) -> dict[str, list[tuple[str, bool]]]:
        creds = self._aws.credentials("plan", "uc-verify-volumes")
        return self._aws.instance_volumes(instance_ids, creds)

    def connection_readiness(self, instance_id: str) -> Readiness:
        creds = self._aws.credentials("plan", "uc-readiness")
        return self._aws.connection_readiness(instance_id, creds)

    def self_check(self) -> dict[str, Any]:
        versions = self.runtime_versions()
        probe = "dep_" + "0" * 32  # deployment IDs have a fixed length
        for role in ("plan", "apply"):
            packed_session_policy(self._settings, role, probe)
        plan_identity = self._aws.verify_role_identity("plan")
        apply_identity = self._aws.verify_role_identity("apply")
        if plan_identity["role"] == apply_identity["role"]:
            raise ProvisioningError("aws_identity_mismatch", "Plan and apply roles are the same.")
        ami_id = self._aws.resolve_ami(self._aws.credentials("plan", "uc-selfcheck-ami"))
        return {
            "terraform_version": versions.terraform_version,
            "provider_versions": versions.provider_versions,
            "plan_role": plan_identity,
            "apply_role": apply_identity,
            "base_image": ami_id,
        }
