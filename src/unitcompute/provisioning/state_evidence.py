"""Strict readers for the state one specific apply left behind.

A Terraform process that exited, normally or by signal, does not prove its effects were
persisted, and an empty or partial snapshot does not prove nothing else was created. So a
state document is accepted as an apply's outcome only if:

- it is a complete raw state envelope (format 4, the pinned Terraform version, lineage,
  serial, outputs and resources all present and well-formed), within the reviewed
  template's two resources;
- its raw outputs agree with its resources;
- it is bound to the saved plan that was applied: same lineage as the plan's prior state
  (when that state had one), a serial no older than it, and resources the plan creates
  carry IDs that were not in the plan's prior state;
- for stored (backend) state, which may be an intermediate or stale snapshot, every
  resource the plan creates is present. ``errored.tfstate`` is written by Terraform only
  with the final state of the apply (``backend/local/backend_apply.go``), so it may
  legitimately show a partial outcome.

Anything else raises ``StateEvidenceError`` and the caller fails closed. Separately,
``observed_identities`` extracts every well-formed ID a document mentions so unaccepted
evidence is still recorded as an observation that must be verified gone.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INSTANCE = "aws_instance.vm"
SECURITY_GROUP = "aws_security_group.vm"
INSTANCE_STATE = "aws_ec2_instance_state.vm"
_PATTERNS = {
    "aws_instance": re.compile(r"^i-[0-9a-f]{8,17}$"),
    "aws_security_group": re.compile(r"^sg-[0-9a-f]{8,17}$"),
    # The power-state resource's ID is the ID of the instance it manages.
    "aws_ec2_instance_state": re.compile(r"^i-[0-9a-f]{8,17}$"),
}
_VOLUME = re.compile(r"^vol-[0-9a-f]{8,17}$")
_ANY_ID = re.compile(r"^(i|vol|sg)-[0-9a-f]{8,17}$")
# Template outputs and the resource each one names.
_OUTPUTS = {"instance_id": INSTANCE, "security_group_id": SECURITY_GROUP, "root_volume_id": None}
MAX_STATE_BYTES = 4 * 1024 * 1024


class StateEvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class AppliedState:
    instance_id: str | None
    security_group_id: str | None
    root_volume_id: str | None
    instance_state_id: str | None = None  # the instance its power-state resource manages


@dataclass(frozen=True)
class PriorState:
    """Lineage and serial of the state a saved plan was computed against."""

    lineage: str
    serial: int


@dataclass(frozen=True)
class StateDocument:
    lineage: str
    serial: int
    applied: AppliedState
    outputs: dict[str, str]


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


def load_state_bytes(data: bytes) -> object:
    if len(data) > MAX_STATE_BYTES:
        raise StateEvidenceError("state document is too large")
    try:
        return json.loads(data)
    except ValueError as exc:
        raise StateEvidenceError("state document is not JSON") from exc


def parse_raw_state(document: object, *, terraform_version: str) -> StateDocument:
    """Parse a complete raw state document (``errored.tfstate`` or ``terraform state pull``)."""
    if not isinstance(document, dict) or document.get("version") != 4:
        raise StateEvidenceError("not a version 4 Terraform state document")
    if document.get("terraform_version") != terraform_version:
        raise StateEvidenceError("state was not written by the pinned Terraform version")
    lineage, serial = document.get("lineage"), document.get("serial")
    if not isinstance(lineage, str) or not lineage:
        raise StateEvidenceError("state has no lineage")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 0:
        raise StateEvidenceError("state has no valid serial")
    resources, raw_outputs = document.get("resources"), document.get("outputs")
    if not isinstance(resources, list):
        raise StateEvidenceError("state resources are missing")
    if not isinstance(raw_outputs, dict):
        raise StateEvidenceError("state outputs are missing")
    found: dict[str, tuple[str, str | None]] = {}
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("mode") != "managed":
            raise StateEvidenceError("state contains a non-managed resource")
        if "module" in resource:
            raise StateEvidenceError("state contains module resources")
        rtype, name = resource.get("type"), resource.get("name")
        if not isinstance(rtype, str) or rtype not in _PATTERNS or name != "vm":
            raise StateEvidenceError(f"unexpected resource {rtype}.{name}")
        instances = resource.get("instances")
        if not isinstance(instances, list) or len(instances) != 1:
            raise StateEvidenceError("resource instances are ambiguous")
        instance = instances[0]
        if not isinstance(instance, dict) or "index_key" in instance:
            raise StateEvidenceError("resource instance is ambiguous")
        if "deposed" in instance:
            raise StateEvidenceError("state contains a deposed object")
        attributes = instance.get("attributes")
        if not isinstance(attributes, dict):
            raise StateEvidenceError(f"{rtype} attributes are not an object")
        if rtype in found:
            raise StateEvidenceError(f"{rtype} appears more than once")
        found[rtype] = _single(attributes, rtype)
    instance_entry = found.get("aws_instance")
    group_entry = found.get("aws_security_group")
    power_entry = found.get("aws_ec2_instance_state")
    applied = AppliedState(
        instance_id=instance_entry[0] if instance_entry else None,
        security_group_id=group_entry[0] if group_entry else None,
        root_volume_id=instance_entry[1] if instance_entry else None,
        instance_state_id=power_entry[0] if power_entry else None,
    )
    if power_entry and (not instance_entry or power_entry[0] != instance_entry[0]):
        raise StateEvidenceError("power state does not belong to the state's instance")
    outputs: dict[str, str] = {}
    for key in _OUTPUTS:
        if key not in raw_outputs:
            continue
        entry = raw_outputs[key]
        value = entry.get("value") if isinstance(entry, dict) else None
        if not isinstance(value, str) or not _ANY_ID.fullmatch(value):
            raise StateEvidenceError(f"output {key} is not a resource id")
        outputs[key] = value
    expected = {
        "instance_id": applied.instance_id,
        "security_group_id": applied.security_group_id,
        "root_volume_id": applied.root_volume_id,
    }
    for key, value in outputs.items():
        if expected[key] != value:
            raise StateEvidenceError(f"output {key} disagrees with the state's resources")
    return StateDocument(lineage, serial, applied, outputs)


def bind_to_plan(
    document: StateDocument,
    *,
    prior: PriorState,
    prior_ids: Collection[str],
    creates: Collection[str],
    require_all_creates: bool,
) -> AppliedState:
    """Accept ``document`` as the outcome of applying the plan, or raise."""
    if prior.lineage and document.lineage != prior.lineage:
        raise StateEvidenceError("state lineage differs from the applied plan's state")
    if document.serial < prior.serial:
        raise StateEvidenceError("state is older than the applied plan's state")
    applied = document.applied
    present = {
        INSTANCE: applied.instance_id,
        SECURITY_GROUP: applied.security_group_id,
        INSTANCE_STATE: applied.instance_state_id,
    }
    if creates and all(present.get(address) is None for address in creates):
        # A state that shows none of what the plan creates says nothing about the apply
        # (it may be stale, or taken before anything was persisted).
        raise StateEvidenceError("state shows none of the resources the plan creates")
    for address in creates:
        if address not in present:
            raise StateEvidenceError(f"plan creates an unexpected resource {address}")
        resource_id = present[address]
        if resource_id is None:
            if require_all_creates:
                raise StateEvidenceError(f"state does not show the created {address}")
            continue
        # The power-state resource is keyed by its instance's ID, which is legitimately in the
        # prior state when the plan only adds this resource to an existing VM.
        if resource_id in prior_ids and address != INSTANCE_STATE:
            raise StateEvidenceError(f"state shows the plan's prior {address}, not a new one")
    if INSTANCE in creates and applied.root_volume_id in prior_ids:
        raise StateEvidenceError("state shows a prior root volume for a new instance")
    return applied


def observed_identities(document: object) -> list[tuple[str, str | None]]:
    """Every well-formed ID in a raw state's resources and outputs, as (id, parent)."""
    if not isinstance(document, dict):
        return []
    found: list[tuple[str, str | None]] = []
    resources = document.get("resources")
    for resource in resources if isinstance(resources, list) else []:
        instances = resource.get("instances") if isinstance(resource, dict) else None
        for instance in instances if isinstance(instances, list) else []:
            attributes = instance.get("attributes") if isinstance(instance, dict) else None
            if not isinstance(attributes, dict):
                continue
            resource_id = attributes.get("id")
            if isinstance(resource_id, str) and _ANY_ID.fullmatch(resource_id):
                found.append((resource_id, None))
            parent = resource_id if isinstance(resource_id, str) else None
            devices = attributes.get("root_block_device")
            for device in devices if isinstance(devices, list) else []:
                volume = device.get("volume_id") if isinstance(device, dict) else None
                if isinstance(volume, str) and _VOLUME.fullmatch(volume):
                    found.append((volume, parent))
    outputs = document.get("outputs")
    if isinstance(outputs, dict):
        instance_output = outputs.get("instance_id")
        parent_output = instance_output.get("value") if isinstance(instance_output, dict) else None
        for key, entry in outputs.items():
            value = entry.get("value") if isinstance(entry, dict) else None
            if isinstance(value, str) and _ANY_ID.fullmatch(value):
                parent = parent_output if key == "root_volume_id" else None
                found.append((value, parent if isinstance(parent, str) else None))
    return found


def prior_state_from_planfile(plan_path: Path) -> PriorState:
    """Lineage and serial of the prior state embedded in a Terraform saved plan."""
    try:
        with zipfile.ZipFile(plan_path) as archive:
            info = archive.getinfo("tfstate")
            if info.file_size > MAX_STATE_BYTES:
                raise StateEvidenceError("plan's prior state is too large")
            data = archive.read(info)
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise StateEvidenceError("saved plan has no readable prior state") from exc
    document = load_state_bytes(data)
    if not isinstance(document, dict) or document.get("version") != 4:
        raise StateEvidenceError("saved plan's prior state is not version 4")
    lineage, serial = document.get("lineage"), document.get("serial")
    if not isinstance(lineage, str) or not isinstance(serial, int) or isinstance(serial, bool):
        raise StateEvidenceError("saved plan's prior state has no lineage or serial")
    return PriorState(lineage, serial)


def read_state_file(path: Path) -> object:
    with open(path, "rb") as handle:
        data = handle.read(MAX_STATE_BYTES + 1)
    return load_state_bytes(data)
