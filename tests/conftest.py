"""Shared fixtures: a local moto server that speaks the EC2/SSM APIs, so the real Terraform
binary and boto3 run end to end with no AWS account, credentials or network."""

from __future__ import annotations

import logging
import os
import shutil
import socket
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto.ec2.models import ec2_backends
from moto.ec2.models.amis import Ami
from moto.server import ThreadedMotoServer
from moto.ssm.models import ssm_backends

from unitcompute_vm import AwsVMs, Network
from unitcompute_vm.aws import IMAGE_SSM_PARAMETER

logging.getLogger("werkzeug").setLevel(logging.ERROR)  # one access-log line per API call

REGION = "us-east-1"
UBUNTU_MIN_GB = 12
WINDOWS_MIN_GB = 30


# moto reports every image's root volume as 15 GiB. Let a test say what an image's minimum is,
# the way real images differ (Ubuntu ~8 GiB, Windows 30 GiB).
_moto_mappings = Ami.block_device_mappings.fget  # type: ignore[attr-defined]
Ami.block_device_mappings = property(  # type: ignore[method-assign, assignment]
    lambda self: [
        {**m, "Ebs": {**m["Ebs"], "VolumeSize": getattr(self, "root_gb", 15)}}
        for m in _moto_mappings(self)
    ]
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Terraform tests skip without a terraform binary, unless REQUIRE_TERRAFORM_TESTS=1."""
    if shutil.which("terraform") or os.environ.get("REQUIRE_TERRAFORM_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="terraform not on PATH")
    for item in items:
        if "terraform" in item.keywords:
            item.add_marker(skip)


@dataclass
class Cloud:
    endpoint: str
    network: Network
    ubuntu_ami: str
    windows_ami: str

    def ec2(self) -> Any:
        return boto3.client("ec2", region_name=REGION)


@pytest.fixture(scope="session")
def moto_endpoint() -> Iterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
    server.start()
    yield f"http://127.0.0.1:{port}"
    server.stop()


@pytest.fixture
def cloud(moto_endpoint: str, monkeypatch: pytest.MonkeyPatch) -> Cloud:
    for key, value in {
        "AWS_ENDPOINT_URL": moto_endpoint,
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)
    ec2 = boto3.client("ec2", region_name=REGION)
    ssm = boto3.client("ssm", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    group = ec2.create_security_group(GroupName="existing", Description="x", VpcId=vpc)["GroupId"]
    images = {}
    for os_name, size in (("ubuntu", UBUNTU_MIN_GB), ("windows", WINDOWS_MIN_GB)):
        images[os_name] = ec2.register_image(
            Name=f"{os_name}-{vpc}",
            RootDeviceName="/dev/sda1",
            BlockDeviceMappings=[
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": size, "VolumeType": "gp3"}}
            ],
        )["ImageId"]
        ec2_backends["123456789012"][REGION].amis[images[os_name]].root_gb = size
        seed = f"/seed/{os_name}"
        ssm.put_parameter(Name=seed, Value=images[os_name], Type="String", Overwrite=True)
        # moto refuses to create names under the AWS-reserved /aws prefix through its API, so move
        # the seeded parameter there inside the (in-process) server. Real AWS publishes these.
        parameters = ssm_backends["123456789012"][REGION]._parameters
        parameters[IMAGE_SSM_PARAMETER[os_name]] = parameters.pop(seed)
    return Cloud(moto_endpoint, Network(subnet, (group,)), images["ubuntu"], images["windows"])


@pytest.fixture
def vms(cloud: Cloud, tmp_path: Path) -> AwsVMs:
    return AwsVMs(tmp_path / "vms", cloud.network, verify_timeout=60, verify_poll=1)
