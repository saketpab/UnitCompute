"""Request/response schemas shared by REST routes and agent tools."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

NAME_PATTERN = r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$"
MIN_DISK_GIB = 8
MAX_DISK_GIB = 30
ID_PATTERN = r"^(dep|plan|job|chat)_[0-9a-f]{32}$"
DEPLOYMENT_ID_PATTERN = r"^dep_[0-9a-f]{32}$"
PLAN_ID_PATTERN = r"^plan_[0-9a-f]{32}$"
JOB_ID_PATTERN = r"^job_[0-9a-f]{32}$"
SESSION_ID_PATTERN = r"^chat_[0-9a-f]{32}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._:-]{8,128}$"

DeploymentName = Annotated[str, StringConstraints(pattern=NAME_PATTERN)]
DiskGiB = Annotated[int, Field(ge=MIN_DISK_GIB, le=MAX_DISK_GIB)]

DeploymentStatus = Literal[
    "planning",
    "awaiting_approval",
    "plan_failed",
    "applying",
    "active",
    "deletion_planning",
    "awaiting_deletion_approval",
    "deleting",
    "deleted",
    "recovery_required",
]
JobStatus = Literal["queued", "running", "succeeded", "failed", "recovery_required"]
PlanKind = Literal["create", "destroy"]


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class DeploymentRequest(StrictRequest):
    name: DeploymentName = Field(description="3-32 chars: lowercase letters, digits, hyphens.")
    disk_gib: DiskGiB = Field(description="Encrypted gp3 root disk size in GiB (8-30).")


class ApprovalRequest(StrictRequest):
    plan_id: Annotated[str, StringConstraints(pattern=PLAN_ID_PATTERN)]
    plan_hash: Annotated[str, StringConstraints(pattern=SHA256_PATTERN)] = Field(
        description="SHA-256 of the saved plan exactly as displayed in the preview."
    )


class AgentMessageRequest(StrictRequest):
    session_id: Annotated[str, StringConstraints(pattern=SESSION_ID_PATTERN)] | None = None
    message: Annotated[str, StringConstraints(min_length=1, max_length=8000)]


class AcceptedResponse(BaseModel):
    deployment_id: str
    plan_id: str
    job_id: str
    status: DeploymentStatus


class CostLine(BaseModel):
    item: str
    monthly_usd: str
    basis: str


class CostEstimate(BaseModel):
    currency: Literal["USD"] = "USD"
    monthly_total_usd: str
    hours_per_month: int
    lines: list[CostLine]
    price_snapshot: dict[str, Any]
    excluded: list[str]
    disclaimer: str


class ResourceChange(BaseModel):
    address: str
    resource_type: str
    action: str
    summary: dict[str, Any]


class PlanPreview(BaseModel):
    plan_id: str
    kind: PlanKind
    status: str
    plan_hash: str | None
    expires_at: datetime | None
    created_at: datetime
    resource_changes: list[ResourceChange]
    warnings: list[str]
    cost: CostEstimate | None
    error: dict[str, Any] | None
    provenance: dict[str, Any]


class JobSummary(BaseModel):
    id: str
    deployment_id: str
    plan_id: str
    kind: Literal["plan", "apply"]
    plan_kind: PlanKind
    status: JobStatus
    created_at: datetime
    started_at: datetime | None
    heartbeat_at: datetime | None
    finished_at: datetime | None
    error: dict[str, Any] | None
    result: dict[str, Any] | None


class AccessInstructions(BaseModel):
    method: Literal["ssm-session-manager"] = "ssm-session-manager"
    ready: bool = Field(
        description="True once EC2 status checks pass and SSM reports this instance Online."
    )
    command: str | None
    requirements: list[str]


class DeploymentDetail(BaseModel):
    id: str
    name: str
    disk_gib: int
    region: str
    instance_type: str
    provisioner: str
    status: DeploymentStatus
    status_reason: str | None
    created_at: datetime
    updated_at: datetime
    current_plan: PlanPreview | None
    latest_job: JobSummary | None
    resources: dict[str, Any] | None
    access: AccessInstructions | None


class DeploymentList(BaseModel):
    deployments: list[DeploymentDetail]


class Proposal(BaseModel):
    name: str
    disk_gib: int
    region: str
    instance_type: str
    estimated_monthly_usd: str
    next_step: str


class AgentReply(BaseModel):
    session_id: str
    reply: str
    model: str
    proposal: Proposal | None
    clarifications: list[str]
    tool_calls: list[str]
    approval_note: str


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str | None
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody
