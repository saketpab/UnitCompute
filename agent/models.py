"""Data models shared by the agent workflow and future API."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AgentIntent(BaseModel):
    """The EC2 capability requested by the user."""

    action: Literal['create', 'delete', 'list', 'view_details']
    resource: Literal['ec2']

    @field_validator('resource', mode='before')
    @classmethod
    def normalize_ec2_resource(cls, value: object) -> object:
        """Accept common model/user synonyms while preserving one canonical value."""
        if not isinstance(value, str):
            return value

        normalized = value.strip().lower()
        ec2_synonyms = {
            'ec2',
            'ec2 server',
            'server',
            'virtual machine',
            'vm',
        }
        return 'ec2' if normalized in ec2_synonyms else normalized


class VMRequest(BaseModel):
    """Information extracted from a user's natural-language request."""

    operating_system: Literal['ubuntu', 'windows'] | None = None
    compute_size: Literal['small', 'medium', 'large'] | None = None
    region: str | None = None
    disk_gb: int | None = Field(default=None, ge=8, le=100)
    name: str | None = None
    purpose: str | None = None
    subnet_id: str | None = None
    security_group_id: str | None = None


class VMPlan(BaseModel):
    """A user-reviewable plan produced before provisioning."""

    region: str
    image_ssm_parameter: str
    instance_type: str
    disk_gb: int
    name: str
    purpose: str | None = None
    subnet_id: str | None = None
    security_group_id: str | None = None


class ResolvedVMPlan(BaseModel):
    """A fully resolved plan that is safe to send to the AWS provisioner."""

    region: str
    availability_zone: str
    ami_id: str
    instance_type: str
    disk_gb: int
    subnet_id: str
    security_group_id: str
    instance_profile_arn: str
    name: str
    tags: dict[str, str]
    client_token: str
