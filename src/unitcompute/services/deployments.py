"""Authorization-aware deployment operations used by both REST routes and agent tools.

Every method takes the verified ``Principal``; ownership is always checked against the
stored owner and failures are reported as non-enumerating 404s.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from unitcompute.auth import Principal
from unitcompute.config import INSTANCE_TYPE, ProvisionerKind, Settings
from unitcompute.db.database import Database, from_db_time, to_db_time, utcnow
from unitcompute.errors import Conflict, NotFound, ServiceUnavailable
from unitcompute.logging_setup import redact
from unitcompute.provisioning.base import (
    TEMPLATE_VERSION,
    PlanKind,
    lock_provider_versions,
    template_hash,
)
from unitcompute.provisioning.terraform import PINNED_TERRAFORM_VERSION, state_key
from unitcompute.schemas import (
    AcceptedResponse,
    AccessInstructions,
    ApprovalRequest,
    CostEstimate,
    DeploymentDetail,
    DeploymentRequest,
    JobSummary,
    PlanPreview,
    ResourceChange,
)

Clock = Callable[[], datetime]

PLANNABLE: dict[PlanKind, set[str]] = {
    "create": {
        "awaiting_approval",
        "plan_failed",
        "recovery_required",
        "active",
        "awaiting_deletion_approval",
    },
    "destroy": {
        "awaiting_approval",
        "plan_failed",
        "recovery_required",
        "active",
        "awaiting_deletion_approval",
    },
}
APPROVABLE_STATUS: dict[PlanKind, str] = {
    "create": "awaiting_approval",
    "destroy": "awaiting_deletion_approval",
}
_SAFE_DETAIL = re.compile(r"^[A-Za-z0-9_.:@/ -]{0,200}$")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def canonical_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def execution_binding(settings: Settings, deployment_id: str) -> str:
    """Hash of everything that decides where and as whom a saved plan executes.

    A plan approved under one account, network, profile, state backend or role set must not
    run after any of them changes; the saved plan would still target the old values."""
    return canonical_hash(
        {
            "provisioner": settings.provisioner.value,
            "region": settings.aws_region,
            "account_id": settings.aws_account_id,
            "vpc_id": settings.vpc_id,
            "subnet_id": settings.subnet_id,
            "instance_profile_name": settings.instance_profile_name,
            "state_bucket": settings.state_bucket,
            "state_key": state_key(deployment_id),
            "plan_role_arn": settings.plan_role_arn,
            "apply_role_arn": settings.apply_role_arn,
        }
    )


def binding_problem(settings: Settings, plan: sqlite3.Row) -> str | None:
    if not plan["execution_hash"] or not hmac.compare_digest(
        plan["execution_hash"], execution_binding(settings, plan["deployment_id"])
    ):
        return "The AWS account, network, profile, state backend or roles changed since this plan."
    if plan["state_key"] != state_key(plan["deployment_id"]):
        return "The plan's state backend key does not belong to this deployment."
    if settings.provisioner is ProvisionerKind.TERRAFORM and (
        plan["account_id"] != settings.aws_account_id
    ):
        return "The plan was produced in a different AWS account."
    return None


def expected_versions(provisioner: str) -> dict[str, Any]:
    """Versions a plan must have been produced with to be approvable/applicable now."""
    if provisioner == ProvisionerKind.SIMULATED:
        return {
            "template_version": TEMPLATE_VERSION,
            "template_hash": template_hash(),
            "terraform_version": "simulated",
            "provider_versions": {"registry.terraform.io/hashicorp/aws": "simulated"},
        }
    return {
        "template_version": TEMPLATE_VERSION,
        "template_hash": template_hash(),
        "terraform_version": PINNED_TERRAFORM_VERSION,
        "provider_versions": lock_provider_versions(),
    }


def plan_versions(plan: sqlite3.Row) -> dict[str, Any]:
    return {
        "template_version": plan["template_version"],
        "template_hash": plan["template_hash"],
        "terraform_version": plan["terraform_version"],
        "provider_versions": json.loads(plan["provider_versions_json"] or "null"),
    }


def record_audit(
    conn: sqlite3.Connection,
    *,
    actor: str,
    action: str,
    deployment_id: str | None = None,
    plan_id: str | None = None,
    job_id: str | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> None:
    safe: dict[str, Any] = {}
    for key, value in (detail or {}).items():
        if isinstance(value, bool | int) or value is None:
            safe[key] = value
        elif isinstance(value, str):
            cleaned = redact(value)[:200]
            safe[key] = cleaned if _SAFE_DETAIL.fullmatch(cleaned) else "[omitted]"
    conn.execute(
        "INSERT INTO audit_events (occurred_at, actor, action, deployment_id, plan_id, job_id, "
        "request_id, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            to_db_time(now or utcnow()),
            actor,
            action,
            deployment_id,
            plan_id,
            job_id,
            request_id,
            json.dumps(safe, sort_keys=True),
        ),
    )


def _dt(value: str | None) -> datetime | None:
    return from_db_time(value) if value else None


class DeploymentService:
    def __init__(self, db: Database, settings: Settings, clock: Clock = utcnow) -> None:
        self._db = db
        self._settings = settings
        self._clock = clock

    # ----------------------------------------------------------------- helpers

    def _require_provisioning(self) -> str:
        kind = self._settings.provisioner
        if kind is ProvisionerKind.DISABLED:
            raise ServiceUnavailable(
                "Provisioning is disabled in this environment. Set "
                "UNITCOMPUTE_PROVISIONER=simulated for offline development.",
                code="provisioning_disabled",
            )
        return kind.value

    @staticmethod
    def _owned_deployment(
        conn: sqlite3.Connection, principal: Principal, deployment_id: str
    ) -> sqlite3.Row:
        row: sqlite3.Row | None = conn.execute(
            "SELECT * FROM deployments WHERE id = ? AND owner_id = ?",
            (deployment_id, principal.subject),
        ).fetchone()
        if row is None:
            raise NotFound("Deployment not found.")
        return row

    @staticmethod
    def _idempotent_replay(
        conn: sqlite3.Connection,
        principal: Principal,
        scope: str,
        key: str | None,
        payload_hash: str,
    ) -> tuple[int, dict[str, Any]] | None:
        if key is None:
            return None
        row = conn.execute(
            "SELECT payload_hash, status_code, response_json FROM idempotency_records "
            "WHERE owner_id = ? AND scope = ? AND idempotency_key = ?",
            (principal.subject, scope, key),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["payload_hash"], payload_hash):
            raise Conflict(
                "This Idempotency-Key was already used with a different request.",
                code="idempotency_key_reused",
            )
        return int(row["status_code"]), json.loads(row["response_json"])

    def _store_idempotency(
        self,
        conn: sqlite3.Connection,
        principal: Principal,
        scope: str,
        key: str | None,
        payload_hash: str,
        status_code: int,
        response: dict[str, Any],
    ) -> None:
        if key is None:
            return
        conn.execute(
            "INSERT INTO idempotency_records (owner_id, scope, idempotency_key, payload_hash, "
            "status_code, response_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                principal.subject,
                scope,
                key,
                payload_hash,
                status_code,
                json.dumps(response),
                to_db_time(self._clock()),
            ),
        )

    def _enqueue_plan(
        self,
        conn: sqlite3.Connection,
        deployment: sqlite3.Row,
        kind: PlanKind,
        provisioner: str,
        payload_hash: str,
        idempotency: tuple[str, str] | None,
    ) -> tuple[str, str]:
        now = to_db_time(self._clock())
        conn.execute(
            "UPDATE plans SET status = 'superseded' WHERE deployment_id = ? "
            "AND status IN ('pending', 'ready')",
            (deployment["id"],),
        )
        plan_id, job_id = new_id("plan"), new_id("job")
        config_hash = canonical_hash(
            {
                "name": deployment["name"],
                "disk_gib": deployment["disk_gib"],
                "region": deployment["region"],
                "instance_type": deployment["instance_type"],
                "kind": kind,
            }
        )
        conn.execute(
            "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
            "config_hash, region, state_key, template_version, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)",
            (
                plan_id,
                deployment["id"],
                deployment["owner_id"],
                kind,
                provisioner,
                config_hash,
                deployment["region"],
                state_key(deployment["id"]),
                TEMPLATE_VERSION,
                now,
            ),
        )
        try:
            conn.execute(
                "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
                "idempotency_scope, idempotency_key, payload_hash, created_at) "
                "VALUES (?, ?, ?, ?, 'plan', 'queued', ?, ?, ?, ?)",
                (
                    job_id,
                    deployment["owner_id"],
                    deployment["id"],
                    plan_id,
                    idempotency[0] if idempotency else None,
                    idempotency[1] if idempotency else None,
                    payload_hash,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise Conflict(
                "Another job is already running for this deployment.", code="job_in_progress"
            ) from exc
        status = "planning" if kind == "create" else "deletion_planning"
        conn.execute(
            "UPDATE deployments SET status = ?, status_reason = NULL, current_plan_id = ?, "
            "updated_at = ? WHERE id = ?",
            (status, plan_id, now, deployment["id"]),
        )
        return plan_id, job_id

    # --------------------------------------------------------------- mutations

    def create_deployment(
        self,
        principal: Principal,
        request: DeploymentRequest,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> tuple[int, dict[str, Any]]:
        provisioner = self._require_provisioning()
        scope = "POST /deployments"
        payload_hash = canonical_hash({"scope": scope, "body": request.model_dump()})
        with self._db.transaction() as conn:
            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)
            if replay:
                return replay
            live = conn.execute(
                "SELECT id FROM deployments WHERE owner_id = ? AND status <> 'deleted'",
                (principal.subject,),
            ).fetchone()
            if live is not None:
                raise Conflict(
                    "You already have a VM (or one being prepared). Delete it before "
                    "creating another.",
                    code="quota_exceeded",
                    details={"deployment_id": live["id"]},
                )
            deployment_id = new_id("dep")
            now = to_db_time(self._clock())
            try:
                conn.execute(
                    "INSERT INTO deployments (id, owner_id, name, disk_gib, region, "
                    "instance_type, provisioner, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'planning', ?, ?)",
                    (
                        deployment_id,
                        principal.subject,
                        request.name,
                        request.disk_gib,
                        self._settings.aws_region,
                        INSTANCE_TYPE,
                        provisioner,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("You already have a VM.", code="quota_exceeded") from exc
            deployment = conn.execute(
                "SELECT * FROM deployments WHERE id = ?", (deployment_id,)
            ).fetchone()
            plan_id, job_id = self._enqueue_plan(
                conn,
                deployment,
                "create",
                provisioner,
                payload_hash,
                (scope, idempotency_key) if idempotency_key else None,
            )
            record_audit(
                conn,
                actor=principal.subject,
                action="deployment.requested",
                deployment_id=deployment_id,
                plan_id=plan_id,
                job_id=job_id,
                request_id=request_id,
                detail={"name": request.name, "disk_gib": request.disk_gib},
            )
            response = AcceptedResponse(
                deployment_id=deployment_id, plan_id=plan_id, job_id=job_id, status="planning"
            ).model_dump()
            self._store_idempotency(
                conn, principal, scope, idempotency_key, payload_hash, 202, response
            )
        return 202, response

    def request_plan(
        self,
        principal: Principal,
        deployment_id: str,
        kind: PlanKind,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> tuple[int, dict[str, Any]]:
        provisioner = self._require_provisioning()
        route = "plan" if kind == "create" else "deletion-plan"
        scope = f"POST /deployments/{deployment_id}/{route}"
        payload_hash = canonical_hash({"scope": scope})
        with self._db.transaction() as conn:
            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)
            if replay:
                return replay
            deployment = self._owned_deployment(conn, principal, deployment_id)
            if deployment["status"] not in PLANNABLE[kind]:
                raise Conflict(
                    f"A {route} cannot be requested while the deployment is "
                    f"{deployment['status']}.",
                    code="invalid_state",
                )
            if deployment["provisioner"] != provisioner:
                raise Conflict(
                    "This deployment belongs to a different provisioner.",
                    code="provisioner_mismatch",
                )
            plan_id, job_id = self._enqueue_plan(
                conn,
                deployment,
                kind,
                provisioner,
                payload_hash,
                (scope, idempotency_key) if idempotency_key else None,
            )
            record_audit(
                conn,
                actor=principal.subject,
                action="plan.requested" if kind == "create" else "deletion_plan.requested",
                deployment_id=deployment_id,
                plan_id=plan_id,
                job_id=job_id,
                request_id=request_id,
            )
            status = "planning" if kind == "create" else "deletion_planning"
            response = AcceptedResponse(
                deployment_id=deployment_id, plan_id=plan_id, job_id=job_id, status=status
            ).model_dump()
            self._store_idempotency(
                conn, principal, scope, idempotency_key, payload_hash, 202, response
            )
        return 202, response

    def approve(
        self,
        principal: Principal,
        deployment_id: str,
        approval: ApprovalRequest,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> tuple[int, dict[str, Any]]:
        provisioner = self._require_provisioning()
        scope = f"POST /deployments/{deployment_id}/approve"
        payload_hash = canonical_hash({"scope": scope, "body": approval.model_dump()})
        now_dt = self._clock()
        now = to_db_time(now_dt)
        with self._db.transaction() as conn:
            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)
            if replay:
                return replay
            deployment = self._owned_deployment(conn, principal, deployment_id)
            plan = conn.execute(
                "SELECT * FROM plans WHERE id = ? AND deployment_id = ? AND owner_id = ?",
                (approval.plan_id, deployment_id, principal.subject),
            ).fetchone()
            if plan is None or deployment["current_plan_id"] != plan["id"]:
                raise Conflict(
                    "That plan is not the current plan for this deployment.",
                    code="plan_not_current",
                )
            if plan["status"] != "ready":
                raise Conflict(
                    f"The plan is {plan['status']} and cannot be approved.",
                    code="plan_not_approvable",
                )
            if from_db_time(plan["expires_at"]) <= now_dt:
                conn.execute("UPDATE plans SET status = 'expired' WHERE id = ?", (plan["id"],))
                record_audit(
                    conn,
                    actor=principal.subject,
                    action="plan.approval_rejected",
                    deployment_id=deployment_id,
                    plan_id=plan["id"],
                    request_id=request_id,
                    detail={"reason": "expired"},
                )
                # Commit the expiry, then report it.
                expired = True
            else:
                expired = False
            if not expired:
                if not hmac.compare_digest(plan["plan_hash"] or "", approval.plan_hash):
                    raise Conflict(
                        "The plan hash does not match the displayed plan.",
                        code="plan_hash_mismatch",
                    )
                if plan["provisioner"] != provisioner or plan_versions(plan) != expected_versions(
                    provisioner
                ):
                    raise Conflict(
                        "The plan was produced with a different template or tool version; "
                        "request a fresh preview.",
                        code="plan_stale",
                    )
                binding = binding_problem(self._settings, plan)
                if binding:
                    raise Conflict(f"{binding} Request a fresh preview.", code="plan_stale")
                if deployment["status"] != APPROVABLE_STATUS[plan["kind"]]:
                    raise Conflict(
                        "The deployment is not waiting for this approval.", code="invalid_state"
                    )
                job_id = new_id("job")
                try:
                    conn.execute(
                        "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
                        "idempotency_scope, idempotency_key, payload_hash, created_at) "
                        "VALUES (?, ?, ?, ?, 'apply', 'queued', ?, ?, ?, ?)",
                        (
                            job_id,
                            principal.subject,
                            deployment_id,
                            plan["id"],
                            scope if idempotency_key else None,
                            idempotency_key,
                            payload_hash,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise Conflict(
                        "Another job is already running for this deployment.",
                        code="job_in_progress",
                    ) from exc
                conn.execute(
                    "UPDATE plans SET status = 'approved', approved_by = ?, approved_at = ? "
                    "WHERE id = ? AND status = 'ready'",
                    (principal.subject, now, plan["id"]),
                )
                status = "applying" if plan["kind"] == "create" else "deleting"
                conn.execute(
                    "UPDATE deployments SET status = ?, status_reason = NULL, updated_at = ? "
                    "WHERE id = ?",
                    (status, now, deployment_id),
                )
                record_audit(
                    conn,
                    actor=principal.subject,
                    action="plan.approved",
                    deployment_id=deployment_id,
                    plan_id=plan["id"],
                    job_id=job_id,
                    request_id=request_id,
                    detail={"kind": plan["kind"], "plan_hash": plan["plan_hash"]},
                )
                response = AcceptedResponse(
                    deployment_id=deployment_id,
                    plan_id=plan["id"],
                    job_id=job_id,
                    status=status,
                ).model_dump()
                self._store_idempotency(
                    conn, principal, scope, idempotency_key, payload_hash, 202, response
                )
        if expired:
            raise Conflict(
                "The plan expired; request a fresh preview and approve that.", code="plan_expired"
            )
        return 202, response

    # ------------------------------------------------------------------- reads

    def list_deployments(self, principal: Principal) -> list[DeploymentDetail]:
        with self._db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM deployments WHERE owner_id = ? ORDER BY rowid DESC LIMIT 50",
                (principal.subject,),
            ).fetchall()
            return [self._detail(conn, row) for row in rows]

    def get_deployment(self, principal: Principal, deployment_id: str) -> DeploymentDetail:
        with self._db.read() as conn:
            return self._detail(conn, self._owned_deployment(conn, principal, deployment_id))

    def get_job(self, principal: Principal, job_id: str) -> JobSummary:
        with self._db.read() as conn:
            row = conn.execute(
                "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
                "ON plans.id = jobs.plan_id WHERE jobs.id = ? AND jobs.owner_id = ?",
                (job_id, principal.subject),
            ).fetchone()
            if row is None:
                raise NotFound("Job not found.")
            return self._job(row)

    @staticmethod
    def _job(row: sqlite3.Row) -> JobSummary:
        error = (
            {"code": row["error_code"], "message": row["error_message"]}
            if row["error_code"]
            else None
        )
        return JobSummary(
            id=row["id"],
            deployment_id=row["deployment_id"],
            plan_id=row["plan_id"],
            kind=row["kind"],
            plan_kind=row["plan_kind"],
            status=row["status"],
            created_at=from_db_time(row["created_at"]),
            started_at=_dt(row["started_at"]),
            heartbeat_at=_dt(row["heartbeat_at"]),
            finished_at=_dt(row["finished_at"]),
            error=error,
            result=json.loads(row["result_json"]) if row["result_json"] else None,
        )

    def _plan_preview(self, plan: sqlite3.Row) -> PlanPreview:
        status = plan["status"]
        expires_at = _dt(plan["expires_at"])
        if status == "ready" and expires_at is not None and expires_at <= self._clock():
            status = "expired"
        error = (
            {"code": plan["error_code"], "message": plan["error_message"]}
            if plan["error_code"]
            else None
        )
        preview = json.loads(plan["preview_json"]) if plan["preview_json"] else {}
        account = plan["account_id"]
        return PlanPreview(
            plan_id=plan["id"],
            kind=plan["kind"],
            status=status,
            plan_hash=plan["plan_hash"],
            expires_at=expires_at,
            created_at=from_db_time(plan["created_at"]),
            resource_changes=[ResourceChange(**c) for c in preview.get("changes", [])],
            warnings=preview.get("warnings", []),
            cost=CostEstimate(**json.loads(plan["cost_json"])) if plan["cost_json"] else None,
            error=error,
            provenance={
                "provisioner": plan["provisioner"],
                "template_version": plan["template_version"],
                "terraform_version": plan["terraform_version"],
                "provider_versions": json.loads(plan["provider_versions_json"] or "null"),
                "region": plan["region"],
                "ami_id": plan["ami_id"],
                "aws_account": f"****{account[-4:]}" if account else None,
            },
        )

    def _detail(self, conn: sqlite3.Connection, row: sqlite3.Row) -> DeploymentDetail:
        plan = None
        if row["current_plan_id"]:
            plan_row = conn.execute(
                "SELECT * FROM plans WHERE id = ?", (row["current_plan_id"],)
            ).fetchone()
            plan = self._plan_preview(plan_row) if plan_row else None
        job_row = conn.execute(
            "SELECT jobs.*, plans.kind AS plan_kind FROM jobs JOIN plans "
            "ON plans.id = jobs.plan_id WHERE jobs.deployment_id = ? "
            "ORDER BY jobs.rowid DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        resources = None
        access = None
        if row["instance_id"] and row["status"] not in {"deleted"}:
            resources = {
                "instance_id": row["instance_id"],
                "security_group_id": row["security_group_id"],
                "root_volume_id": row["root_volume_id"],
                "connection": {
                    "ready": bool(row["connection_ready"]),
                    "ec2_status_checks": row["ec2_status"],
                    "ssm_ping_status": row["ssm_ping_status"],
                    "checked_at": row["readiness_checked_at"],
                },
            }
            simulated = row["provisioner"] == ProvisionerKind.SIMULATED
            command = (
                f"aws ssm start-session --target {row['instance_id']} --region {row['region']}"
            )
            ready = bool(row["connection_ready"])
            requirements = (
                ["Simulated deployment: there is no real VM to connect to."]
                if simulated
                else [
                    "An AWS IAM identity allowed to call ssm:StartSession on this instance; "
                    "a UnitCompute login alone is not sufficient.",
                    "AWS CLI v2 with the Session Manager plugin installed.",
                    "No inbound ports are open, so SSH and other direct access are unavailable.",
                ]
            )
            if not ready:
                requirements.append(
                    "Not ready yet: sessions fail until EC2 status checks pass and SSM reports "
                    "the instance Online (see resources.connection)."
                )
            access = AccessInstructions(
                ready=ready, command=None if simulated else command, requirements=requirements
            )
        return DeploymentDetail(
            id=row["id"],
            name=row["name"],
            disk_gib=row["disk_gib"],
            region=row["region"],
            instance_type=row["instance_type"],
            provisioner=row["provisioner"],
            status=row["status"],
            status_reason=row["status_reason"],
            created_at=from_db_time(row["created_at"]),
            updated_at=from_db_time(row["updated_at"]),
            current_plan=plan,
            latest_job=self._job(job_row) if job_row else None,
            resources=resources,
            access=access,
        )


def plan_expiry(now: datetime, settings: Settings) -> datetime:
    return now + timedelta(seconds=settings.plan_ttl_seconds)
