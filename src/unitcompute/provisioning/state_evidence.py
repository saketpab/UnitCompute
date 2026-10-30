"""Strict readers for the state written by one specific apply.

Two inputs are accepted: ``errored.tfstate`` (Terraform's raw state format, written to the
working directory when the backend write fails) and ``terraform show -json`` of the stored
state (read without refreshing). Anything outside the reviewed template's two resources,
or any shape that cannot be interpreted unambiguously, raises ``StateEvidenceError``;
callers then fail closed instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_PATTERNS = {
    "aws_instance": re.compile(r"^i-[0-9a-f]{8,17}$"),
    "aws_security_group": re.compile(r"^sg-[0-9a-f]{8,17}$"),
}
_VOLUME = re.compile(r"^vol-[0-9a-f]{8,17}$")


class StateEvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class AppliedState:
    instance_id: str | None
    security_group_id: str | None
    root_volume_id: str | None


def _single(values: dict[str, Any], rtype: str) -> tuple[str, str | None]:
    resource_id = values.get("id")
    if not isinstance(resource_id, str) or not _PATTERNS[rtype].fullmatch(resource_id):
        raise StateEvidenceError(f"{rtype} has no valid id")
    root: str | None = None
    if rtype == "aws_instance":
        devices = values.get("root_block_device")
        if devices in (None, []):
            raise StateEvidenceError("aws_instance has no root_block_device")
        if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
            raise StateEvidenceError("aws_instance root_block_device is ambiguous")
        volume = devices[0].get("volume_id")
        if not isinstance(volume, str) or not _VOLUME.fullmatch(volume):
            raise StateEvidenceError("aws_instance root volume id is invalid")
        root = volume
    return resource_id, root


def _collect(
    found: dict[str, tuple[str, str | None]], rtype: str, name: object, values: object
) -> None:
    if rtype not in _PATTERNS or name != "vm":
        raise StateEvidenceError(f"unexpected resource {rtype}.{name}")
    if not isinstance(values, dict):
        raise StateEvidenceError(f"{rtype} attributes are not an object")
    if rtype in found:
        raise StateEvidenceError(f"{rtype} appears more than once")
    found[rtype] = _single(values, rtype)


def _result(found: dict[str, tuple[str, str | None]]) -> AppliedState:
    instance = found.get("aws_instance")
    group = found.get("aws_security_group")
    return AppliedState(
        instance_id=instance[0] if instance else None,
        security_group_id=group[0] if group else None,
        root_volume_id=instance[1] if instance else None,
    )


def from_raw_state(document: object) -> AppliedState:
    """Parse Terraform's raw state file format (version 4), e.g. errored.tfstate."""
    if not isinstance(document, dict) or document.get("version") != 4:
        raise StateEvidenceError("not a version 4 Terraform state document")
    resources = document.get("resources", [])
    if not isinstance(resources, list):
        raise StateEvidenceError("state resources are not a list")
    found: dict[str, tuple[str, str | None]] = {}
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("mode") != "managed":
            raise StateEvidenceError("state contains a non-managed resource")
        if "module" in resource:
            raise StateEvidenceError("state contains module resources")
        instances = resource.get("instances")
        if not isinstance(instances, list) or len(instances) > 1:
            raise StateEvidenceError("resource instances are ambiguous")
        for instance in instances:
            if not isinstance(instance, dict) or "index_key" in instance:
                raise StateEvidenceError("resource instance is ambiguous")
            _collect(
                found, str(resource.get("type")), resource.get("name"), instance.get("attributes")
            )
    return _result(found)


def from_show_json(document: object) -> AppliedState:
    """Parse ``terraform show -json`` output for stored (not refreshed) state."""
    if not isinstance(document, dict):
        raise StateEvidenceError("show output is not an object")
    values = document.get("values")
    if values is None:
        return AppliedState(None, None, None)  # empty state
    if not isinstance(values, dict):
        raise StateEvidenceError("show values are not an object")
    root = values.get("root_module", {})
    if not isinstance(root, dict) or root.get("child_modules"):
        raise StateEvidenceError("state contains module resources")
    found: dict[str, tuple[str, str | None]] = {}
    for resource in root.get("resources", []) or []:
        if not isinstance(resource, dict) or resource.get("mode") != "managed":
            raise StateEvidenceError("state contains a non-managed resource")
        if "index" in resource:
            raise StateEvidenceError("resource instance is ambiguous")
        _collect(found, str(resource.get("type")), resource.get("name"), resource.get("values"))
    return _result(found)
