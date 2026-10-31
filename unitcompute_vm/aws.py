"""AWS implementation of the VM lifecycle: Terraform makes the changes, boto3 only reads.

Per-VM folder (``state_root/<vm_id>/``), all of it kept on failure and after deletion:

    vm.json              recorded configuration and status (the desired state)
    terraform.tfstate    Terraform state (+ .backup); losing it orphans the VM
    plans/<id>.tfplan    the exact saved plans, with <id>.json beside each (hash, status, summary)
    logs/                one log per Terraform run
    state-backups/       a copy of the state taken before every apply
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import shutil
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .provider import (
    ApplyFailed,
    Busy,
    Operation,
    OrphansRemain,
    Plan,
    PlanRejected,
    PowerState,
    StalePlan,
    VerificationFailed,
    VMError,
    VMInfo,
)
from .spec import InvalidRequest, VMSpec, check_disk, check_name, check_purpose
from .terraform import Terraform, TerraformFailed

# Mirrors the mappings in agent_exploration.ipynb. Neither image has been launched by this
# project's tests against real AWS.
IMAGE_SSM_PARAMETER = {
    "ubuntu": "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
    "windows": "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base",
}
INSTANCE_TYPE = {"small": "t3.micro", "medium": "t3.small", "large": "t3.medium"}
DEFAULT_MODULE_DIR = Path(__file__).resolve().parent.parent / "terraform" / "aws_vm"
_INSTANCE = "aws_instance.vm"
_STATE = "aws_ec2_instance_state.vm"
_RESOURCES = frozenset({_INSTANCE, _STATE})
_EDITABLE_INSTANCE_KEYS = {"tags", "tags_all", "volume_tags", "root_block_device"}
_GONE = {"terminated"}  # EC2 keeps a terminated instance listed for about an hour


@dataclass(frozen=True)
class Network:
    """Existing network the VM is placed in. Nothing here is created or changed by this package."""

    subnet_id: str
    security_group_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.subnet_id or not self.security_group_ids:
            raise InvalidRequest("a subnet_id and at least one security group are required")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, path)


def _digest(data: object) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AwsVMs:
    """Create, inspect, edit, stop/start and delete single VMs. See the README for usage."""

    def __init__(
        self,
        state_root: Path | str = "~/.unitcompute/vms",
        network: Network | None = None,
        *,
        terraform: str = "terraform",
        module_dir: Path | str = DEFAULT_MODULE_DIR,
        session: boto3.Session | None = None,
        apply_timeout: float = 1800,
        verify_timeout: float = 180,
        verify_poll: float = 3,
    ) -> None:
        self.state_root = Path(state_root).expanduser().resolve()  # Terraform runs in -chdir
        self.network = network
        self._terraform = shutil.which(terraform) or terraform
        self._module_dir = Path(module_dir).resolve()
        self._session = session or boto3.Session()
        self._apply_timeout = apply_timeout
        self._verify_timeout = verify_timeout
        self._verify_poll = verify_poll

    # ------------------------------------------------------------------ planning

    def plan_create(self, spec: VMSpec) -> Plan:
        if self.network is None:
            raise InvalidRequest(
                "AwsVMs needs a Network (subnet and security groups) to create VMs"
            )
        ami_id, image_min = self._select_image(spec)
        disk = spec.disk_gb if spec.disk_gb is not None else image_min
        if disk < image_min:
            raise InvalidRequest(f"disk_gb {disk} is below this image's minimum of {image_min} GiB")
        if disk > 100:
            raise InvalidRequest(f"the image needs {image_min} GiB, above the 100 GiB maximum")
        vm_id = "vm-" + secrets.token_hex(6)
        record: dict[str, Any] = {
            "vm_id": vm_id,
            "status": "planned",
            "created_at": _now(),
            "region": spec.region,
            "operating_system": spec.operating_system,
            "compute_size": spec.compute_size,
            "instance_type": INSTANCE_TYPE[spec.compute_size],
            "ami_id": ami_id,
            "image_min_gb": image_min,
            "network": asdict(self.network),
            "desired": {
                "name": spec.name,
                "purpose": spec.purpose,
                "disk_gb": disk,
                "power_state": "running",
            },
        }
        with self._locked(vm_id):
            _write_json(self._vm_dir(vm_id) / "vm.json", record)
            return self._make_plan(vm_id, "create", record, record["desired"])

    def plan_update(
        self,
        vm_id: str,
        *,
        name: str | None = None,
        purpose: str | None = None,
        disk_gb: int | None = None,
        power_state: PowerState | None = None,
    ) -> Plan:
        """Edit name, purpose, disk (grow only) and/or power state. Nothing else is editable."""
        with self._locked(vm_id):
            record = self._load(vm_id)
            self._require(record, {"active", "incomplete"}, "edited")
            repair = record["status"] == "incomplete"
            if repair and (left := self.find_orphans(vm_id, record)):
                raise PlanRejected(
                    "cloud resources tagged for this VM are not in the Terraform state "
                    f"({', '.join(left)}); inspect them, then terminate_orphans() or delete"
                )
            creatable: frozenset[str] = frozenset()
            if repair:
                # A repair finishes what an interrupted create never reached. Once the state
                # holds the instance, a missing one is a lost VM, never a resource to build anew.
                held = self._tf(vm_id).instance(self._vm_dir(vm_id) / "logs" / "repair.log")
                creatable = frozenset({_STATE} if held else _RESOURCES)
            desired = dict(record["desired"])
            if name is not None:
                desired["name"] = check_name(name)
            if purpose is not None:
                desired["purpose"] = check_purpose(purpose)
            if disk_gb is not None:
                if check_disk(disk_gb) < desired["disk_gb"]:
                    raise InvalidRequest(
                        f"disk can only grow: {disk_gb} GiB is below {desired['disk_gb']} GiB"
                    )
                desired["disk_gb"] = disk_gb
            if power_state is not None:
                if power_state not in ("running", "stopped"):
                    raise InvalidRequest("power_state must be 'running' or 'stopped'")
                desired["power_state"] = power_state
            return self._make_plan(vm_id, "update", record, desired, creatable=creatable)

    def plan_delete(self, vm_id: str) -> Plan:
        with self._locked(vm_id):
            record = self._load(vm_id)
            self._require(record, {"planned", "active", "incomplete"}, "deleted")
            return self._make_plan(vm_id, "delete", record, record["desired"])

    def _make_plan(
        self,
        vm_id: str,
        operation: Operation,
        record: dict[str, Any],
        after: dict[str, Any],
        *,
        creatable: frozenset[str] = frozenset(),
    ) -> Plan:
        plan_id = f"{datetime.now(UTC):%Y%m%dT%H%M%S}-{operation}-{secrets.token_hex(3)}"
        vm_dir = self._vm_dir(vm_id)
        tf = self._tf(vm_id)
        plan_file = vm_dir / "plans" / f"{plan_id}.tfplan"
        var_file = vm_dir / "plans" / f"{plan_id}.vars.json"
        log = vm_dir / "logs" / f"{plan_id}.plan.log"
        _write_json(var_file, self._tfvars(vm_id, record, after))
        try:
            tf.init(log)
            tf.plan(var_file, plan_file, log, destroy=operation == "delete")
            shown = tf.show_plan(plan_file, log)
        except TerraformFailed as exc:
            raise VMError(f"{exc}; see {log}") from exc
        changes = _check_plan(operation, shown, creatable)
        summary = _summary(operation, record["desired"], after, changes)
        sha = _sha256(plan_file)
        _write_json(
            vm_dir / "plans" / f"{plan_id}.json",
            {
                "plan_id": plan_id,
                "operation": operation,
                "sha256": sha,
                "base": _digest(record["desired"]),
                "after": after,
                "changes": changes,
                "summary": summary,
                "status": "planned",
                "created_at": _now(),
            },
        )
        return Plan(plan_id, vm_id, operation, sha, summary, tuple(map(tuple, changes)))  # type: ignore[arg-type]

    @staticmethod
    def _tfvars(vm_id: str, record: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
        return {
            "vm_id": vm_id,
            "name": desired["name"],
            "purpose": desired["purpose"],
            "disk_gb": desired["disk_gb"],
            "power_state": desired["power_state"],
            "region": record["region"],
            "ami_id": record["ami_id"],
            "instance_type": record["instance_type"],
            "subnet_id": record["network"]["subnet_id"],
            "security_group_ids": list(record["network"]["security_group_ids"]),
        }

    def _select_image(self, spec: VMSpec) -> tuple[str, int]:
        """Resolve the OS to an image ID once, and read that image's minimum root size."""
        try:
            ssm = self._session.client("ssm", region_name=spec.region)
            ami_id = ssm.get_parameter(Name=IMAGE_SSM_PARAMETER[spec.operating_system])[
                "Parameter"
            ]["Value"]
            image = self._session.client("ec2", region_name=spec.region).describe_images(
                ImageIds=[ami_id]
            )["Images"][0]
        except (BotoCoreError, ClientError, IndexError) as exc:
            raise VMError(f"could not resolve the {spec.operating_system} image: {exc}") from exc
        root = [
            m["Ebs"]["VolumeSize"]
            for m in image.get("BlockDeviceMappings", [])
            if m.get("DeviceName") == image.get("RootDeviceName")
            and "VolumeSize" in m.get("Ebs", {})
        ]
        if not root:
            raise VMError(f"image {ami_id} reports no root volume size")
        return ami_id, int(root[0])

    # ------------------------------------------------------------------ applying

    def apply(self, plan: Plan) -> VMInfo:
        """Apply exactly the saved plan, then check the cloud shows the result."""
        with self._locked(plan.vm_id):
            record = self._load(plan.vm_id)
            plan_json = self._vm_dir(plan.vm_id) / "plans" / f"{plan.plan_id}.json"
            plan_file = plan_json.with_suffix(".tfplan")
            saved = json.loads(plan_json.read_text()) if plan_json.exists() else None
            if saved is None or not plan_file.exists():
                raise StalePlan(f"plan {plan.plan_id} is not saved for {plan.vm_id}")
            if saved["status"] != "planned":
                raise StalePlan(f"plan {plan.plan_id} was already used ({saved['status']})")
            if not plan.sha256 == saved["sha256"] == _sha256(plan_file):
                raise StalePlan(f"plan {plan.plan_id} differs from the one that was reviewed")
            if saved["base"] != _digest(record["desired"]):
                raise StalePlan(
                    f"plan {plan.plan_id} is out of date: the VM changed since it was made"
                )

            vm_dir = self._vm_dir(plan.vm_id)
            tf = self._tf(plan.vm_id)
            log = vm_dir / "logs" / f"{plan.plan_id}.apply.log"
            if tf.state_path.exists():
                (vm_dir / "state-backups").mkdir(exist_ok=True)
                shutil.copy2(tf.state_path, vm_dir / "state-backups" / f"{plan.plan_id}.tfstate")
            # Written before Terraform starts so a crash leaves "incomplete", never "active".
            if plan.operation != "delete":
                record["desired"] = saved["after"]
            record["status"] = "incomplete"
            record["last_plan"] = plan.plan_id
            saved["status"] = "applying"
            _write_json(vm_dir / "vm.json", record)
            _write_json(plan_json, saved)
            try:
                tf.apply(plan_file, log, timeout=self._apply_timeout)
            except TerraformFailed as exc:
                saved["status"] = "interrupted" if exc.interrupted else "failed"
                _write_json(plan_json, saved)
                raise ApplyFailed(
                    f"{exc}. State and plan are kept; plan again to repair or delete", str(log)
                ) from exc
            saved["status"] = "applied"
            _write_json(plan_json, saved)

            if plan.operation == "delete":
                self._wait_gone(plan.vm_id, record)
                record["status"] = "deleted"
            else:
                self._wait_matches(plan.vm_id, record)
                record["status"] = "active"
            _write_json(vm_dir / "vm.json", record)
            return self._inspect(plan.vm_id, record)

    # ------------------------------------------------------------------ reading

    def inspect(self, vm_id: str) -> VMInfo:
        return self._inspect(vm_id, self._load(vm_id))

    def _inspect(self, vm_id: str, record: dict[str, Any]) -> VMInfo:
        desired = record["desired"]
        problems: list[str] = []
        instance_id: str | None = None
        live: dict[str, Any] = {}
        if record["status"] != "planned":
            tracked = self._tf(vm_id).instance(self._vm_dir(vm_id) / "logs" / "inspect.log")
            instance_id = tracked[0] if tracked else None
            if instance_id:
                live = self._read_instance(record, instance_id)
                if not live:
                    problems.append(f"instance {instance_id} was not found in AWS")
            elif record["status"] == "active":
                problems.append("the Terraform state records no instance")
        if live and record["status"] == "active":
            problems += _mismatches(desired, live)
        if record["status"] in ("incomplete", "deleted"):
            if orphans := self.find_orphans(vm_id, record):
                problems.append("untracked resources: " + ", ".join(orphans))
        if record["status"] == "incomplete":
            problems.append(f"plan {record.get('last_plan')} did not finish; plan again to repair")
        return VMInfo(
            vm_id=vm_id,
            status=record["status"],
            name=desired["name"],
            operating_system=record["operating_system"],
            compute_size=record["compute_size"],
            region=record["region"],
            disk_gb=desired["disk_gb"],
            desired_power_state=desired["power_state"],
            instance_id=instance_id,
            power_state=live.get("state"),
            live_disk_gb=live.get("disk_gb"),
            public_ip=live.get("public_ip"),
            private_ip=live.get("private_ip"),
            problems=tuple(problems),
        )

    def _read_instance(self, record: dict[str, Any], instance_id: str) -> dict[str, Any]:
        ec2 = self._session.client("ec2", region_name=record["region"])
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"].startswith("InvalidInstanceID"):
                return {}
            raise
        instance = reservations[0]["Instances"][0]
        volumes = [
            m["Ebs"]["VolumeId"]
            for m in instance.get("BlockDeviceMappings", [])
            if m.get("DeviceName") == instance.get("RootDeviceName")
        ]
        disk = None
        if volumes:
            disk = ec2.describe_volumes(VolumeIds=volumes)["Volumes"][0]["Size"]
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        return {
            "state": instance["State"]["Name"],
            "disk_gb": disk,
            "name": tags.get("Name"),
            "purpose": tags.get("Purpose"),
            "public_ip": instance.get("PublicIpAddress"),
            "private_ip": instance.get("PrivateIpAddress"),
        }

    def _wait_matches(self, vm_id: str, record: dict[str, Any]) -> None:
        """Poll EC2 until it shows the desired state; a transitional state is not a result."""
        deadline = time.monotonic() + self._verify_timeout
        while True:
            info = self._inspect(vm_id, {**record, "status": "active"})
            if info.consistent and info.power_state == record["desired"]["power_state"]:
                return
            if time.monotonic() >= deadline:
                seen = "; ".join(info.problems) or f"power state {info.power_state}"
                raise VerificationFailed(f"{vm_id} does not match after apply: {seen}")
            time.sleep(self._verify_poll)

    def _wait_gone(self, vm_id: str, record: dict[str, Any]) -> None:
        deadline = time.monotonic() + self._verify_timeout
        while True:
            left = self.find_orphans(vm_id, record)
            if not left:
                return
            if time.monotonic() >= deadline:
                raise OrphansRemain(left)
            time.sleep(self._verify_poll)

    # ------------------------------------------------------------------ orphans

    def find_orphans(self, vm_id: str, record: dict[str, Any] | None = None) -> list[str]:
        """Live instances and volumes tagged for this VM that Terraform state does not track."""
        record = record or self._load(vm_id)
        known = set(self._tf(vm_id).instance(self._vm_dir(vm_id) / "logs" / "inspect.log") or ())
        ec2 = self._session.client("ec2", region_name=record["region"])
        tag = [{"Name": "tag:UnitComputeVm", "Values": [vm_id]}]
        found = [
            i["InstanceId"]
            for r in ec2.describe_instances(Filters=tag)["Reservations"]
            for i in r["Instances"]
            if i["State"]["Name"] not in _GONE
        ]
        found += [
            v["VolumeId"]
            for v in ec2.describe_volumes(Filters=tag)["Volumes"]
            if v["State"] not in ("deleting", "deleted")
        ]
        return sorted(set(found) - known)

    def terminate_orphans(self, vm_id: str) -> list[str]:
        """Explicit cleanup of ``find_orphans``: terminate instances, delete volumes. Only for a
        VM that is deleted or incomplete, and only resources tagged with this VM's ID."""
        with self._locked(vm_id):
            record = self._load(vm_id)
            self._require(record, {"incomplete", "deleted"}, "cleaned of orphans")
            ids = self.find_orphans(vm_id, record)
            ec2 = self._session.client("ec2", region_name=record["region"])
            instances = [i for i in ids if i.startswith("i-")]
            if instances:
                ec2.terminate_instances(InstanceIds=instances)
                ec2.get_waiter("instance_terminated").wait(InstanceIds=instances)
            for volume in (v for v in ids if v.startswith("vol-")):
                try:
                    ec2.delete_volume(VolumeId=volume)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                        raise
            return ids

    # ------------------------------------------------------------------ plumbing

    def _vm_dir(self, vm_id: str) -> Path:
        if not vm_id.startswith("vm-") or not vm_id[3:].isalnum():
            raise InvalidRequest(f"{vm_id!r} is not a VM id")
        return self.state_root / vm_id

    def _tf(self, vm_id: str) -> Terraform:
        return Terraform(self._terraform, self._module_dir, self._vm_dir(vm_id))

    def _load(self, vm_id: str) -> dict[str, Any]:
        path = self._vm_dir(vm_id) / "vm.json"
        if not path.exists():
            raise InvalidRequest(f"unknown VM {vm_id!r} under {self.state_root}")
        loaded: dict[str, Any] = json.loads(path.read_text())
        return loaded

    @staticmethod
    def _require(record: dict[str, Any], allowed: set[str], verb: str) -> None:
        if record["status"] not in allowed:
            raise InvalidRequest(f"{record['vm_id']} is {record['status']} and cannot be {verb}")

    @contextmanager
    def _locked(self, vm_id: str) -> Iterator[None]:
        """One mutating call per VM at a time. If we hold the lock, no apply is running, so a plan
        still marked ``applying`` died with its process."""
        vm_dir = self._vm_dir(vm_id)
        vm_dir.mkdir(parents=True, exist_ok=True)
        with (vm_dir / ".lock").open("w") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Busy(f"{vm_id} is being changed by another process") from exc
            for path in (vm_dir / "plans").glob("*.json"):
                if path.name.endswith(".vars.json"):
                    continue
                saved = json.loads(path.read_text())
                if saved.get("status") == "applying":
                    saved["status"] = "interrupted"
                    _write_json(path, saved)
            yield


def _mismatches(desired: dict[str, Any], live: dict[str, Any]) -> list[str]:
    out = []
    if live["state"] != desired["power_state"]:
        out.append(f"power state is {live['state']}, expected {desired['power_state']}")
    if live["disk_gb"] != desired["disk_gb"]:
        out.append(f"root disk is {live['disk_gb']} GiB, expected {desired['disk_gb']}")
    if live["name"] != desired["name"]:
        out.append(f"Name tag is {live['name']!r}, expected {desired['name']!r}")
    return out


def _check_plan(
    operation: Operation, shown: dict[str, Any], creatable: frozenset[str]
) -> list[list[str]]:
    """Reject any plan outside the supported lifecycle; return the (address, action) changes.

    ``creatable`` names the resources an update may create: only those a repair of an
    interrupted create never reached."""
    changes: list[list[str]] = []
    for rc in shown.get("resource_changes", []):
        address, change = rc["address"], rc["change"]
        actions = [a for a in change["actions"] if a != "no-op"]
        if not actions:
            continue
        if address not in _RESOURCES:
            raise PlanRejected(f"plan touches {address}, which is not part of a VM")
        allowed = {"create": ["create"], "update": ["update"], "delete": ["delete"]}[operation]
        if actions != allowed and not (actions == ["create"] and address in creatable):
            gone = " (it no longer exists in AWS; delete this VM and create a new one)"
            raise PlanRejected(
                f"{operation} plan wants to {'+'.join(actions)} {address}"
                + (gone if actions == ["create"] and address == _INSTANCE else "")
            )
        if operation == "update" and actions == ["update"]:
            _check_update(address, change)
        changes.append([address, actions[0]])
    return changes


def _check_update(address: str, change: dict[str, Any]) -> None:
    old, new = change["before"], change["after"]
    changed = {k for k in set(old) | set(new) if old.get(k) != new.get(k)}
    if address == _STATE:
        if changed != {"state"} or new.get("force"):
            raise PlanRejected("the power-state resource may only change its state")
        return
    if not changed <= _EDITABLE_INSTANCE_KEYS:
        raise PlanRejected(
            "instance changes beyond tags and disk size: " + ", ".join(sorted(changed))
        )
    for old_dev, new_dev in zip(old["root_block_device"], new["root_block_device"], strict=False):
        other = {k for k in set(old_dev) | set(new_dev) if old_dev.get(k) != new_dev.get(k)}
        if other - {"volume_size"}:
            raise PlanRejected("root disk changes beyond its size: " + ", ".join(sorted(other)))
        if new_dev["volume_size"] < old_dev["volume_size"]:
            raise PlanRejected("the root disk cannot shrink")


def _summary(
    operation: Operation, before: dict[str, Any], after: dict[str, Any], changes: list[list[str]]
) -> str:
    if operation == "delete":
        head = "Delete the VM and its root disk (data on it is lost)."
    elif operation == "create":
        head = (
            f"Create VM {after['name']!r}: {after['disk_gb']} GiB root disk, "
            f"power state {after['power_state']}."
        )
    else:
        edits = [f"{k}: {before[k]!r} -> {after[k]!r}" for k in after if before.get(k) != after[k]]
        head = (
            "Edit "
            + ("; ".join(edits) if edits else "nothing (re-checks the VM against AWS)")
            + "."
        )
    lines = [f"  {action} {address}" for address, action in changes] or ["  no resource changes"]
    return "\n".join([head, *lines])
