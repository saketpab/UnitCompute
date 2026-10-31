"""The provider-neutral description of a VM and the resolution of a partial request into one.

``resolve_request`` is the single place where an optional-everything request (the notebook's
``VMRequest``) becomes something that can be planned: it names every missing required input at
once instead of failing on the first, and applies the few defaults that were approved.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

OperatingSystem = Literal["ubuntu", "windows"]
ComputeSize = Literal["small", "medium", "large"]

DEFAULT_REGION = "us-east-1"
MIN_DISK_GB = 8
MAX_DISK_GB = 100
REQUIRED_FIELDS = ("name", "operating_system", "compute_size")
OPERATING_SYSTEMS = ("ubuntu", "windows")
COMPUTE_SIZES = ("small", "medium", "large")

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")


class MissingInputs(ValueError):
    """Required inputs are absent; ``fields`` lists all of them so the caller can ask once."""

    def __init__(self, fields: list[str]) -> None:
        self.fields = fields
        super().__init__("missing required VM inputs: " + ", ".join(fields))


class InvalidRequest(ValueError):
    """A supplied value is not acceptable (bad name, unknown region, disk out of range...)."""


@dataclass(frozen=True)
class VMSpec:
    """What the user asked for. ``disk_gb=None`` means "the selected image's minimum"."""

    name: str
    operating_system: OperatingSystem
    compute_size: ComputeSize
    region: str = DEFAULT_REGION
    disk_gb: int | None = None
    purpose: str = ""


def check_name(name: object) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise InvalidRequest(
            f"name {name!r} must be 1-63 characters: letters, digits, '.', '_' or '-', "
            "starting with a letter or digit"
        )
    return name


def check_purpose(purpose: object) -> str:
    if not isinstance(purpose, str) or len(purpose) > 256 or not purpose.isprintable():
        raise InvalidRequest("purpose must be printable text of at most 256 characters")
    return purpose


def check_disk(disk_gb: object) -> int:
    if (
        not isinstance(disk_gb, int)
        or isinstance(disk_gb, bool)
        or not MIN_DISK_GB <= disk_gb <= MAX_DISK_GB
    ):
        raise InvalidRequest(f"disk_gb must be a whole number from {MIN_DISK_GB} to {MAX_DISK_GB}")
    return disk_gb


def check_region(region: object) -> str:
    if not isinstance(region, str) or not _REGION.fullmatch(region):
        raise InvalidRequest(f"region {region!r} does not look like an AWS region name")
    from botocore.session import get_session  # offline: botocore ships its endpoint table

    if region not in get_session().get_available_regions("ec2"):
        raise InvalidRequest(f"region {region!r} is not a known AWS region")
    return region


def resolve_request(
    request: Mapping[str, Any] | Any, *, default_region: str = DEFAULT_REGION
) -> VMSpec:
    """Turn a (possibly partial) request into a ``VMSpec`` or say exactly what is missing.

    ``request`` is a mapping or any object with ``model_dump()`` (the notebook's ``VMRequest``).
    Required: name, operating_system, compute_size. Defaulted: region (``default_region``) and
    disk (the image minimum, decided when the VM is planned). ``purpose`` is optional.
    """
    data = dict(request) if isinstance(request, Mapping) else dict(request.model_dump())
    missing = [f for f in REQUIRED_FIELDS if data.get(f) in (None, "")]
    if missing:
        raise MissingInputs(missing)
    os_name, size = data["operating_system"], data["compute_size"]
    if os_name not in OPERATING_SYSTEMS:
        raise InvalidRequest(f"operating_system {os_name!r} must be one of {OPERATING_SYSTEMS}")
    if size not in COMPUTE_SIZES:
        raise InvalidRequest(f"compute_size {size!r} must be one of {COMPUTE_SIZES}")
    disk = data.get("disk_gb")
    return VMSpec(
        name=check_name(data["name"]),
        operating_system=os_name,
        compute_size=size,
        region=check_region(data.get("region") or default_region),
        disk_gb=None if disk is None else check_disk(disk),
        purpose=check_purpose(data.get("purpose") or ""),
    )
