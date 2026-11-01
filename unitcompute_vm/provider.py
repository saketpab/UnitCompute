"""The values and errors a caller sees when working with one VM, with no AWS or Terraform in sight.

Every change is two calls. A ``plan_*`` call saves an exact plan and returns it for review;
``apply`` runs precisely that saved plan (and nothing else), then reads the result back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Operation = Literal["create", "update", "delete"]
PowerState = Literal["running", "stopped"]


class VMError(Exception):
    """Base class for everything this package raises on purpose."""


class PlanRejected(VMError):
    """The plan would do something outside the supported lifecycle (replace, shrink, ...)."""


class StalePlan(VMError):
    """The plan may not be applied now: changed on disk, already used, or superseded."""


class Busy(VMError):
    """Another process is changing this VM."""


class ApplyFailed(VMError):
    """The apply did not complete. State, plan and log are kept; ``log`` is the path."""

    def __init__(self, message: str, log: str) -> None:
        super().__init__(f"{message} (log: {log})")
        self.log = log


class VerificationFailed(VMError):
    """The apply finished but the cloud does not show the planned result. Nothing is rolled back."""


class OrphansRemain(VMError):
    """Resources tagged for this VM are still in the cloud after a destroy."""

    def __init__(self, ids: list[str]) -> None:
        self.ids = ids
        super().__init__("still present in the cloud: " + ", ".join(ids))


@dataclass(frozen=True)
class Plan:
    """A saved plan. ``sha256`` is the digest of the exact saved plan file the caller reviewed."""

    plan_id: str
    vm_id: str
    operation: Operation
    sha256: str
    summary: str
    changes: tuple[tuple[str, str], ...] = ()  # (resource address, action)

    @property
    def no_changes(self) -> bool:
        return not self.changes


@dataclass(frozen=True)
class VMInfo:
    """The recorded configuration next to what the cloud reports now."""

    vm_id: str
    status: str  # planned | active | incomplete | deleted
    name: str
    operating_system: str
    compute_size: str
    region: str
    disk_gb: int
    desired_power_state: PowerState
    instance_id: str | None = None
    power_state: str | None = None  # the cloud's instance state, e.g. running, stopped
    live_disk_gb: int | None = None
    public_ip: str | None = None
    private_ip: str | None = None
    problems: tuple[str, ...] = field(default=())  # differences between record and cloud

    @property
    def consistent(self) -> bool:
        return not self.problems
