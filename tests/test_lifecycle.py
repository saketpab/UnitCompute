"""The VM lifecycle through the real Terraform binary and the real module, against a local moto
server standing in for AWS. Nothing here talks to AWS."""

from __future__ import annotations

import dataclasses
import json
import shutil
import stat
import subprocess
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from conftest import UBUNTU_MIN_GB, WINDOWS_MIN_GB, Cloud

from unitcompute_vm import (
    ApplyFailed,
    AwsVMs,
    InvalidRequest,
    Network,
    PlanRejected,
    StalePlan,
    resolve_request,
)

pytestmark = pytest.mark.terraform

REQUEST = {"name": "web-test", "operating_system": "ubuntu", "compute_size": "small"}


def tagged(cloud: Cloud, vm_id: str) -> list[dict[str, object]]:
    ec2 = cloud.ec2()
    out = []
    flt = [{"Name": "tag:UnitComputeVm", "Values": [vm_id]}]
    for r in ec2.describe_instances(Filters=flt)["Reservations"]:
        out += [i for i in r["Instances"] if i["State"]["Name"] != "terminated"]
    return out + [
        v for v in ec2.describe_volumes(Filters=flt)["Volumes"] if v["State"] != "deleting"
    ]


def create(vms: AwsVMs, **changes: object) -> str:
    plan = vms.plan_create(resolve_request({**REQUEST, **changes}))
    vms.apply(plan)
    return plan.vm_id


def test_create_edit_stop_start_delete(vms: AwsVMs, cloud: Cloud, tmp_path: Path) -> None:
    plan = vms.plan_create(resolve_request({**REQUEST, "purpose": "web testing"}))
    vm_id = plan.vm_id
    assert [a for _, a in plan.changes] == ["create", "create"]
    assert f"{UBUNTU_MIN_GB} GiB" in plan.summary  # disk defaulted to the image minimum
    assert tagged(cloud, vm_id) == []  # planning created nothing

    # Only the exact reviewed plan file may be applied.
    with pytest.raises(StalePlan, match="differs"):
        vms.apply(dataclasses.replace(plan, sha256="0" * 64))
    assert tagged(cloud, vm_id) == []

    info = vms.apply(plan)
    assert (info.status, info.power_state, info.live_disk_gb) == (
        "active",
        "running",
        UBUNTU_MIN_GB,
    )
    assert info.consistent and info.instance_id
    instance = cloud.ec2().describe_instances(InstanceIds=[info.instance_id])["Reservations"][0]
    tags = {t["Key"]: t["Value"] for t in instance["Instances"][0]["Tags"]}
    assert tags["Name"] == "web-test" and tags["Purpose"] == "web testing"
    assert instance["Instances"][0]["SubnetId"] == cloud.network.subnet_id
    with pytest.raises(StalePlan, match="already used"):
        vms.apply(plan)

    # A new process (a fresh AwsVMs on the same folder) sees the same VM.
    again = AwsVMs(vms.state_root, None, verify_timeout=60, verify_poll=1).inspect(vm_id)
    assert again == info

    # Edit: rename + grow. Only the instance changes; Terraform and EC2 agree afterwards.
    edit = vms.plan_update(vm_id, name="web-renamed", disk_gb=20)
    assert edit.changes == (("aws_instance.vm", "update"),)
    assert "'web-test' -> 'web-renamed'" in edit.summary and "12 -> 20" in edit.summary
    info = vms.apply(edit)
    assert (info.name, info.live_disk_gb, info.consistent) == ("web-renamed", 20, True)
    assert vms.plan_update(vm_id).no_changes  # Terraform state matches the recorded config
    with pytest.raises(InvalidRequest, match="only grow"):
        vms.plan_update(vm_id, disk_gb=15)

    # Stop, then start: a one-attribute change each, recorded in state, verified in EC2.
    stop = vms.plan_update(vm_id, power_state="stopped")
    assert stop.changes == (("aws_ec2_instance_state.vm", "update"),)
    info = vms.apply(stop)
    assert (info.power_state, info.desired_power_state, info.consistent) == (
        "stopped",
        "stopped",
        True,
    )
    assert vms.plan_update(vm_id).no_changes
    info = vms.apply(vms.plan_update(vm_id, power_state="running"))
    assert (info.power_state, info.consistent) == ("running", True)

    # Delete: nothing tagged is left, the folder with state, plans and logs is kept.
    delete = vms.plan_delete(vm_id)
    assert "data on it is lost" in delete.summary
    info = vms.apply(delete)
    assert info.status == "deleted" and tagged(cloud, vm_id) == []
    vm_dir = vms.state_root / vm_id
    assert (vm_dir / "terraform.tfstate").exists() and list((vm_dir / "logs").glob("*.apply.log"))
    assert (vm_dir / "plans" / f"{plan.plan_id}.tfplan").exists()  # reviewed plans are kept
    with pytest.raises(InvalidRequest, match="deleted"):
        vms.plan_update(vm_id, name="again")


def test_a_second_plan_from_the_same_base_cannot_be_applied_after_the_first(vms: AwsVMs) -> None:
    vm_id = create(vms)
    first = vms.plan_update(vm_id, name="first")
    second = vms.plan_update(vm_id, name="second")
    vms.apply(first)
    with pytest.raises(StalePlan, match="out of date"):
        vms.apply(second)
    assert vms.inspect(vm_id).name == "first"


def test_windows_uses_its_own_image_and_minimum_disk(vms: AwsVMs, cloud: Cloud) -> None:
    too_small = {**REQUEST, "operating_system": "windows", "disk_gb": WINDOWS_MIN_GB - 1}
    with pytest.raises(InvalidRequest, match="below this image's minimum of 30"):
        vms.plan_create(resolve_request(too_small))
    plan = vms.plan_create(resolve_request({**REQUEST, "operating_system": "windows"}))
    assert f"{WINDOWS_MIN_GB} GiB" in plan.summary
    info = vms.apply(plan)
    assert info.operating_system == "windows" and info.live_disk_gb == WINDOWS_MIN_GB
    assert vms.inspect(plan.vm_id).instance_id
    image = cloud.ec2().describe_instances(InstanceIds=[info.instance_id or ""])
    assert image["Reservations"][0]["Instances"][0]["ImageId"] == cloud.windows_ami


def test_out_of_band_changes_are_reported_and_a_vanished_instance_is_not_recreated(
    vms: AwsVMs, cloud: Cloud
) -> None:
    vm_id = create(vms)
    instance_id = vms.inspect(vm_id).instance_id or ""
    cloud.ec2().stop_instances(InstanceIds=[instance_id])
    drifted = vms.inspect(vm_id)
    assert not drifted.consistent and "power state is stopped" in drifted.problems[0]
    assert vms.apply(vms.plan_update(vm_id)).consistent  # re-applies the recorded state

    cloud.ec2().terminate_instances(InstanceIds=[instance_id])
    with pytest.raises(PlanRejected, match="create"):
        vms.plan_update(vm_id, name="renamed")  # would silently build a different VM


def test_inspect_says_so_when_aws_no_longer_knows_the_instance(vms: AwsVMs, cloud: Cloud) -> None:
    vm_id = create(vms)

    class AgedOut:
        """A session whose DescribeInstances answers like AWS does for an instance that is gone."""

        def client(self, name: str, **kwargs: object) -> object:
            client = boto3.Session().client(name, **kwargs)
            if name == "ec2":

                def not_found(**_: object) -> None:
                    error = {"Error": {"Code": "InvalidInstanceID.NotFound", "Message": "gone"}}
                    raise ClientError(error, "DescribeInstances")

                client.describe_instances = not_found
            return client

    info = AwsVMs(vms.state_root, None, session=AgedOut()).inspect(vm_id)  # type: ignore[arg-type]
    assert info.status == "active" and info.power_state is None
    assert not info.consistent and "was not found in AWS" in info.problems[0]


def test_repair_after_a_failed_edit_never_recreates_the_instance(
    vms: AwsVMs, cloud: Cloud, tmp_path: Path
) -> None:
    vm_id = create(vms)
    instance_id = vms.inspect(vm_id).instance_id or ""
    failing = AwsVMs(vms.state_root, None, terraform=stub(tmp_path, FAIL_APPLY), verify_poll=1)
    with pytest.raises(ApplyFailed, match="exited with status 1"):
        failing.apply(failing.plan_update(vm_id, name="renamed"))
    assert vms.inspect(vm_id).status == "incomplete"

    cloud.ec2().terminate_instances(InstanceIds=[instance_id])
    with pytest.raises(PlanRejected, match="no longer exists in AWS"):
        vms.plan_update(vm_id)
    assert vms.apply(vms.plan_delete(vm_id)).status == "deleted"  # the way out
    assert tagged(cloud, vm_id) == []


def test_repair_after_an_interrupted_delete_never_builds_a_new_vm(
    vms: AwsVMs, cloud: Cloud, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm_id = create(vms)

    def process_died(*_: object, **__: object) -> None:
        raise RuntimeError("process died after Terraform finished the delete")

    with monkeypatch.context() as patched:
        patched.setattr(AwsVMs, "_wait_gone", process_died)
        with pytest.raises(RuntimeError, match="process died"):
            vms.apply(vms.plan_delete(vm_id))
    assert tagged(cloud, vm_id) == []  # Terraform really deleted it
    assert vms.inspect(vm_id).status == "incomplete"  # but the wrapper never finalized
    assert vms.inspect(vm_id).instance_id is None  # and the state no longer holds an instance

    for edit in ({}, {"name": "renamed"}, {"power_state": "stopped"}):
        with pytest.raises(PlanRejected, match="no longer exists"):
            vms.plan_update(vm_id, **edit)  # type: ignore[arg-type]
    assert vms.apply(vms.plan_delete(vm_id)).status == "deleted"  # recovery is to finish deleting
    assert tagged(cloud, vm_id) == []


def test_a_relative_state_folder_works(cloud: Cloud, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    relative = AwsVMs("vms", cloud.network)  # Terraform runs in another directory (-chdir)
    plan = relative.plan_create(resolve_request(REQUEST))
    assert (tmp_path / "vms" / plan.vm_id / "plans" / f"{plan.plan_id}.tfplan").exists()


def test_a_failed_create_keeps_state_and_logs_and_can_be_deleted(
    vms: AwsVMs, cloud: Cloud, tmp_path: Path
) -> None:
    bad = Network("subnet-0123456789abcdef0", cloud.network.security_group_ids)
    broken = AwsVMs(vms.state_root, bad, verify_timeout=5, verify_poll=1)
    plan = broken.plan_create(resolve_request(REQUEST))
    with pytest.raises(ApplyFailed) as err:
        broken.apply(plan)
    log = Path(err.value.log)
    assert "InvalidSubnetID.NotFound" in log.read_text()
    info = broken.inspect(plan.vm_id)
    assert info.status == "incomplete" and not info.consistent
    saved = json.loads((vms.state_root / plan.vm_id / "plans" / f"{plan.plan_id}.json").read_text())
    assert saved["status"] == "failed"

    gone = broken.apply(broken.plan_delete(plan.vm_id))
    assert gone.status == "deleted" and tagged(cloud, plan.vm_id) == []
    assert log.exists()


KILL_AFTER_INSTANCE = """#!/bin/bash
# Real terraform, but an apply is SIGKILLed (no clean shutdown) once the instance exists.
REAL=__REAL__
if [[ "$2" != apply ]]; then exec "$REAL" "$@"; fi
OUT="$(mktemp)"
"$REAL" "$@" > "$OUT" 2>&1 &
PID=$!
until grep -q "aws_instance.vm: Creation complete" "$OUT"; do sleep 0.1; done
kill -9 "$PID"; wait "$PID" 2>/dev/null
cat "$OUT"; exit 137
"""


FAIL_APPLY = """#!/bin/bash
# Real terraform, except that an apply fails before changing anything.
REAL=__REAL__
if [[ "$2" == apply ]]; then echo "injected apply failure"; exit 1; fi
exec "$REAL" "$@"
"""


def stub(tmp_path: Path, script: str) -> str:
    path = tmp_path / f"terraform-stub-{abs(hash(script))}"
    path.write_text(script.replace("__REAL__", str(shutil.which("terraform"))))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def killed_midway(vms: AwsVMs, cloud: Cloud, tmp_path: Path) -> str:
    killer = AwsVMs(
        vms.state_root,
        cloud.network,
        terraform=stub(tmp_path, KILL_AFTER_INSTANCE),
        verify_poll=1,
    )
    plan = killer.plan_create(resolve_request(REQUEST))
    with pytest.raises(ApplyFailed):
        killer.apply(plan)
    saved = json.loads((vms.state_root / plan.vm_id / "plans" / f"{plan.plan_id}.json").read_text())
    assert saved["status"] == "failed"
    return plan.vm_id


def test_an_apply_killed_midway_is_repaired_by_planning_again(
    vms: AwsVMs, cloud: Cloud, tmp_path: Path
) -> None:
    vm_id = killed_midway(vms, cloud, tmp_path)
    info = vms.inspect(vm_id)  # a new process: the instance made it into the saved state
    assert info.status == "incomplete" and not info.consistent and info.instance_id
    assert vms.find_orphans(vm_id) == []

    # Had the wrapper process itself died, its plan would still say "applying"; the next call
    # (which can only hold the VM lock if nothing is running) marks it interrupted.
    plan_json = next((vms.state_root / vm_id / "plans").glob("*-create-*.tfplan")).with_suffix(
        ".json"
    )
    plan_json.write_text(plan_json.read_text().replace('"failed"', '"applying"'))
    repair = vms.plan_update(vm_id)
    assert (
        json.loads(plan_json.read_text())["status"] == "interrupted"
    )  # creates only what the killed apply never reached
    assert repair.changes == (("aws_ec2_instance_state.vm", "create"),)
    info = vms.apply(repair)
    assert (info.status, info.power_state, info.consistent) == ("active", "running", True)


def test_resources_missing_from_state_are_reported_and_removed_only_on_request(
    vms: AwsVMs, cloud: Cloud, tmp_path: Path
) -> None:
    vm_id = killed_midway(vms, cloud, tmp_path)
    (vms.state_root / vm_id / "terraform.tfstate").unlink()  # the state folder was damaged
    (vms.state_root / vm_id / "terraform.tfstate.backup").unlink(missing_ok=True)

    orphans = vms.find_orphans(vm_id)
    assert {o[:2] for o in orphans} == {"i-", "vo"} and len(orphans) == 2
    assert any("untracked resources" in p for p in vms.inspect(vm_id).problems)
    with pytest.raises(PlanRejected, match="not in the Terraform state"):
        vms.plan_update(vm_id)  # would build a second VM next to the first
    assert len(tagged(cloud, vm_id)) == 2  # nothing was touched

    assert sorted(vms.terminate_orphans(vm_id)) == sorted(orphans)
    assert tagged(cloud, vm_id) == []
    assert vms.apply(vms.plan_delete(vm_id)).status == "deleted"


def test_the_module_is_formatted() -> None:
    from unitcompute_vm.aws import DEFAULT_MODULE_DIR

    done = subprocess.run(
        [
            shutil.which("terraform") or "terraform",
            "fmt",
            "-check",
            "-diff",
            str(DEFAULT_MODULE_DIR),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout
