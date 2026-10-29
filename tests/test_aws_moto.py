"""boto3 reads against moto's local AWS emulation. These prove our request/parse logic, not
real AWS IAM, pricing or provisioning behaviour."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from conftest import make_settings
from test_config_and_auth import TERRAFORM_SETTINGS
from unitcompute.provisioning.aws import AwsEnvironment
from unitcompute.provisioning.base import ProvisioningError

DEP = "dep_0123456789abcdef0123456789abcdef"


@pytest.fixture
def aws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[AwsEnvironment]:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        yield AwsEnvironment(make_settings(tmp_path, **TERRAFORM_SETTINGS))


def _launch(tag: str, ami: str) -> str:
    ec2 = boto3.client("ec2", region_name="us-east-1")
    tags = [{"Key": "UnitComputeDeployment", "Value": tag}]
    instance = ec2.run_instances(
        ImageId=ami,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags},
            {"ResourceType": "volume", "Tags": tags},
        ],
    )["Instances"][0]["InstanceId"]
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    ec2.create_security_group(
        GroupName=f"sg-{tag}",
        Description="x",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}],
    )
    return str(instance)


def test_resolve_official_ami(aws: AwsEnvironment) -> None:
    creds = aws.credentials("plan", "uc-test-session")
    assert aws.account_id(creds) == "123456789012"
    ami = aws.resolve_ami(creds)
    assert ami.startswith("ami-")


def test_owned_resources_filters_by_deployment_tag(aws: AwsEnvironment) -> None:
    creds = aws.credentials("plan", "uc-test-session")
    ami = aws.resolve_ami(creds)
    mine = _launch(DEP, ami)
    _launch("dep_" + "f" * 32, ami)
    found = aws.owned_resources(DEP, creds)
    types = sorted(r.resource_type for r in found)
    assert types == ["instance", "security_group", "volume"]
    assert any(r.resource_id == mine for r in found)

    boto3.client("ec2", region_name="us-east-1").terminate_instances(InstanceIds=[mine])
    remaining = {r.resource_type for r in aws.owned_resources(DEP, creds)}
    assert "instance" not in remaining


def test_account_mismatch_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    # Roles resolve to account 123456789012 but the deployment expects 999999999999.
    settings = make_settings(tmp_path, **{**TERRAFORM_SETTINGS, "aws_account_id": "999999999999"})
    with mock_aws():
        env = AwsEnvironment(settings)
        creds = env.credentials("plan", "uc-test-session")
        with pytest.raises(ProvisioningError) as exc:
            env.account_id(creds)
    assert exc.value.code == "aws_account_mismatch"


def test_non_amazon_ami_rejected(aws: AwsEnvironment, monkeypatch: pytest.MonkeyPatch) -> None:
    creds = aws.credentials("plan", "uc-test-session")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    instance = _launch(DEP, aws.resolve_ami(creds))
    custom = ec2.create_image(InstanceId=instance, Name="custom")["ImageId"]
    ssm = boto3.client("ssm", region_name="us-east-1")
    monkeypatch.setattr("unitcompute.provisioning.aws.AL2023_AMI_PARAMETER", "/test/custom-ami")
    ssm.put_parameter(Name="/test/custom-ami", Value=custom, Type="String")
    with pytest.raises(ProvisioningError) as exc:
        aws.resolve_ami(creds)
    assert exc.value.code == "ami_invalid"
