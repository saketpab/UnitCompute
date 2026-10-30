"""Provisioner interface shared by the Terraform implementation and the offline simulator."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from unitcompute.provisioning.state_evidence import PriorState

TEMPLATE_VERSION = "ec2-vm/v1"
TAG_MANAGED_BY = "ManagedBy"
TAG_DEPLOYMENT = "UnitComputeDeployment"
TAG_OWNER = "UnitComputeOwner"
TAG_TEMPLATE = "UnitComputeTemplate"
MANAGED_BY_VALUE = "unitcompute"

PlanKind = Literal["create", "destroy"]


def owner_tag(owner_id: str) -> str:
    """Pseudonymous owner tag so subjects/emails are never written to AWS tags."""
    return hashlib.sha256(owner_id.encode()).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class DeploymentSpec:
    deployment_id: str
    owner_tag: str
    name: str
    disk_gib: int
    region: str
    instance_type: str


@dataclass(frozen=True)
class NetworkTargets:
    account_id: str
    vpc_id: str
    subnet_id: str
    instance_profile_name: str


@dataclass(frozen=True)
class RuntimeVersions:
    template_version: str
    template_hash: str
    terraform_version: str
    provider_versions: dict[str, str]


@dataclass(frozen=True)
class PlanResult:
    plan_path: Path
    plan_hash: str
    plan_json: dict[str, Any]
    account_id: str
    ami_id: str | None
    versions: RuntimeVersions


@dataclass(frozen=True)
class ApplyResult:
    outputs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class OwnedResource:
    resource_type: Literal["instance", "volume", "security_group"]
    resource_id: str
    state: str


@dataclass(frozen=True)
class Readiness:
    """Connection readiness, separate from whether infrastructure was applied."""

    ec2_status: str | None  # "ok" once both EC2 status checks pass
    ssm_status: str | None  # SSM PingStatus for this exact EC2 instance, e.g. "Online"

    @property
    def ready(self) -> bool:
        return self.ec2_status == "ok" and self.ssm_status in {"Online", "Online (simulated)"}


class ProvisioningError(Exception):
    """A failure whose ``safe_message`` may be shown to the resource owner."""

    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(f"{code}: {safe_message}")
        self.code = code
        self.safe_message = safe_message


class ProvisioningTimeout(ProvisioningError):
    pass


class Provisioner(Protocol):
    kind: str

    def runtime_versions(self) -> RuntimeVersions: ...

    def network_targets(self) -> NetworkTargets: ...

    def plan(
        self, spec: DeploymentSpec, kind: PlanKind, workdir: Path, frozen_ami_id: str | None
    ) -> PlanResult:
        """Create a saved plan. ``frozen_ami_id`` is reused once a VM may exist; otherwise
        the current official AMI is resolved and frozen into this plan."""
        ...

    def apply(self, spec: DeploymentSpec, workdir: Path, plan_path: Path) -> ApplyResult: ...

    def capture_stored_state(self, spec: DeploymentSpec, workdir: Path) -> object:
        """The stored state as a raw state document (``terraform state pull``: read-only, no
        refresh), from a plan's initialized work directory. Raises ProvisioningError if it
        cannot be read."""
        ...

    def prior_state(self, plan_path: Path) -> PriorState:
        """Lineage and serial of the state the saved plan was computed against. Raises
        StateEvidenceError if the saved plan does not show them."""
        ...

    def owned_resources(self, deployment_id: str) -> list[OwnedResource]:
        """Resources currently carrying this deployment's tag."""
        ...

    def find_resources(self, resource_ids: list[str]) -> list[OwnedResource]:
        """Look up known instance/volume/security-group IDs directly, regardless of tags.

        Returns those that still exist (instances that are not terminated). Raises
        ProvisioningError when existence cannot be established."""
        ...

    def instance_volumes(self, instance_ids: list[str]) -> dict[str, list[tuple[str, bool]]]:
        """(volume ID, is_root) currently mapped to each instance (absent once terminated).

        ``is_root`` is True only for the mapping on the instance's root device name.
        Instances that are unknown or report no mappings are omitted. Raises
        ProvisioningError when the lookup itself fails."""
        ...

    def connection_readiness(self, instance_id: str) -> Readiness: ...

    def self_check(self) -> dict[str, Any]:
        """Verify tool versions and execution identities; raise ProvisioningError if not."""
        ...


def template_dir() -> Path:
    return Path(__file__).parent / "templates" / "ec2_vm_v1"


def template_hash(directory: Path | None = None) -> str:
    """Hash of the reviewed template files, including the provider lock file."""
    directory = directory or template_dir()
    digest = hashlib.sha256()
    for path in sorted(directory.iterdir()):
        if path.is_file() and (path.suffix == ".tf" or path.name == ".terraform.lock.hcl"):
            digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


_LOCK_VERSION = re.compile(r'provider "([^"]+)" \{\s*version\s*=\s*"([^"]+)"')


def lock_provider_versions(directory: Path | None = None) -> dict[str, str]:
    """Provider versions pinned by the template's committed ``.terraform.lock.hcl``."""
    lock = ((directory or template_dir()) / ".terraform.lock.hcl").read_text(encoding="utf-8")
    return dict(_LOCK_VERSION.findall(lock))
