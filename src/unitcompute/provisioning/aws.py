"""AWS reads and short-lived role credentials used by the Terraform provisioner.

The host's own identity is only used to assume two narrowly scoped roles: a plan role
(read-only EC2/SSM plus the state bucket) and an apply role (scoped mutations). No
long-lived keys are created or stored by the application.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from unitcompute.config import AL2023_AMI_PARAMETER, Settings
from unitcompute.provisioning.base import TAG_DEPLOYMENT, OwnedResource, ProvisioningError

_AMI = re.compile(r"^ami-[0-9a-f]{8,17}$")
_BOTO_CONFIG = Config(
    retries={"max_attempts": 4, "mode": "standard"}, connect_timeout=10, read_timeout=30
)
LIVE_INSTANCE_STATES = ["pending", "running", "shutting-down", "stopping", "stopped"]


@dataclass(frozen=True)
class TemporaryCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime | None = None

    def env(self, region: str) -> dict[str, str]:
        return {
            "AWS_ACCESS_KEY_ID": self.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
            "AWS_SESSION_TOKEN": self.session_token,
            "AWS_REGION": region,
            "AWS_DEFAULT_REGION": region,
        }

    def secrets(self) -> list[str]:
        return [self.access_key_id, self.secret_access_key, self.session_token]

    def __repr__(self) -> str:
        return "TemporaryCredentials(<redacted>)"


SessionFactory = Callable[..., Any]


class AwsEnvironment:
    def __init__(self, settings: Settings, session_factory: SessionFactory | None = None) -> None:
        self._settings = settings
        self._session_factory = session_factory or boto3.session.Session

    def _client(self, service: str, creds: TemporaryCredentials | None = None) -> Any:
        kwargs: dict[str, Any] = {"region_name": self._settings.aws_region}
        if creds is not None:
            kwargs.update(
                aws_access_key_id=creds.access_key_id,
                aws_secret_access_key=creds.secret_access_key,
                aws_session_token=creds.session_token,
            )
        session: Any = self._session_factory(**kwargs)
        return session.client(service, config=_BOTO_CONFIG)

    def credentials(
        self, role: Literal["plan", "apply"], session_name: str
    ) -> TemporaryCredentials:
        arn = self._settings.plan_role_arn if role == "plan" else self._settings.apply_role_arn
        if not arn:
            raise ProvisioningError(
                "aws_not_configured", "The AWS execution role is not configured."
            )
        try:
            response = self._client("sts").assume_role(
                RoleArn=arn, RoleSessionName=session_name[:64], DurationSeconds=3600
            )
        except (ClientError, BotoCoreError) as exc:
            raise ProvisioningError(
                "aws_credentials_unavailable", "Could not obtain AWS execution credentials."
            ) from exc
        c = response["Credentials"]
        return TemporaryCredentials(
            access_key_id=c["AccessKeyId"],
            secret_access_key=c["SecretAccessKey"],
            session_token=c["SessionToken"],
            expiration=c.get("Expiration"),
        )

    def account_id(self, creds: TemporaryCredentials) -> str:
        try:
            account = str(self._client("sts", creds).get_caller_identity()["Account"])
        except (ClientError, BotoCoreError) as exc:
            raise ProvisioningError("aws_unavailable", "Could not verify the AWS account.") from exc
        if account != self._settings.aws_account_id:
            raise ProvisioningError(
                "aws_account_mismatch", "Execution credentials belong to an unexpected account."
            )
        return account

    def resolve_ami(self, creds: TemporaryCredentials) -> str:
        """Resolve the current official Amazon Linux 2023 x86_64 AMI, to be frozen in the plan."""
        try:
            parameter = self._client("ssm", creds).get_parameter(Name=AL2023_AMI_PARAMETER)
            ami_id = str(parameter["Parameter"]["Value"])
            if not _AMI.fullmatch(ami_id):
                raise ProvisioningError("ami_invalid", "The AMI parameter returned an invalid ID.")
            images = self._client("ec2", creds).describe_images(ImageIds=[ami_id])["Images"]
        except (ClientError, BotoCoreError) as exc:
            raise ProvisioningError("aws_unavailable", "Could not resolve the base image.") from exc
        if len(images) != 1:
            raise ProvisioningError("ami_invalid", "The base image could not be verified.")
        image = images[0]
        if (
            image.get("ImageOwnerAlias") != "amazon"
            or image.get("Architecture") != "x86_64"
            or image.get("State") != "available"
            or image.get("Platform") == "windows"
        ):
            raise ProvisioningError("ami_invalid", "The base image is not an official AL2023 AMI.")
        return ami_id

    def owned_resources(
        self, deployment_id: str, creds: TemporaryCredentials
    ) -> list[OwnedResource]:
        tag_filter = {"Name": f"tag:{TAG_DEPLOYMENT}", "Values": [deployment_id]}
        found: list[OwnedResource] = []
        try:
            ec2 = self._client("ec2", creds)
            for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[
                    tag_filter,
                    {"Name": "instance-state-name", "Values": LIVE_INSTANCE_STATES},
                ]
            ):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        found.append(
                            OwnedResource(
                                "instance", instance["InstanceId"], instance["State"]["Name"]
                            )
                        )
            for page in ec2.get_paginator("describe_volumes").paginate(Filters=[tag_filter]):
                for volume in page["Volumes"]:
                    found.append(OwnedResource("volume", volume["VolumeId"], volume["State"]))
            for page in ec2.get_paginator("describe_security_groups").paginate(
                Filters=[tag_filter]
            ):
                for group in page["SecurityGroups"]:
                    found.append(OwnedResource("security_group", group["GroupId"], "exists"))
        except (ClientError, BotoCoreError) as exc:
            raise ProvisioningError(
                "aws_unavailable", "Could not list deployment resources."
            ) from exc
        return found

    def ssm_ping_status(self, instance_id: str, creds: TemporaryCredentials) -> str | None:
        try:
            info = self._client("ssm", creds).describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )["InstanceInformationList"]
        except (ClientError, BotoCoreError):
            return None
        return str(info[0]["PingStatus"]) if info else "NotRegistered"
