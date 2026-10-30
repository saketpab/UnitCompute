"""FastAPI application: routes, request IDs, size limits, CORS and structured errors."""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from unitcompute.agent.service import AgentService, build_model_factory
from unitcompute.auth import Authenticator, Principal, build_authenticator
from unitcompute.config import ProvisionerKind, Settings
from unitcompute.db.database import LATEST_SCHEMA_VERSION, Database, from_db_time, utcnow
from unitcompute.errors import AppError, InvalidInput
from unitcompute.logging_setup import request_id_var
from unitcompute.schemas import (
    DEPLOYMENT_ID_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    JOB_ID_PATTERN,
    AcceptedResponse,
    AgentMessageRequest,
    AgentReply,
    ApprovalRequest,
    ChatTitle,
    DeploymentDetail,
    DeploymentList,
    DeploymentRequest,
    ErrorResponse,
    JobSummary,
    ProfileUpdate,
)
from unitcompute.services.catalog import CatalogService
from unitcompute.services.deployments import DeploymentService

log = logging.getLogger(__name__)
_IDEMPOTENCY = re.compile(IDEMPOTENCY_KEY_PATTERN)


@dataclass
class Container:
    settings: Settings
    db: Database
    authenticator: Authenticator
    deployments: DeploymentService
    agent: AgentService


def build_container(
    settings: Settings,
    *,
    authenticator: Authenticator | None = None,
    agent: AgentService | None = None,
    deployments: DeploymentService | None = None,
) -> Container:
    db = Database(settings.database_url, settings.database_schema)
    deployments = deployments or DeploymentService(db, settings)
    return Container(
        settings=settings,
        db=db,
        authenticator=authenticator or build_authenticator(settings),
        deployments=deployments,
        agent=agent or AgentService(settings, db, deployments, build_model_factory(settings)),
    )


class BodySizeLimit:
    """Rejects bodies over the limit, whether or not Content-Length is declared."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await _too_large(scope, send, self.max_bytes)
                    return
        # Bodies are small (bounded by max_bytes), so buffer them before the app runs;
        # FastAPI would otherwise turn a mid-stream rejection into a generic 400.
        chunks: list[bytes] = []
        received = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":  # client disconnected
                return
            body = message.get("body", b"")
            received += len(body)
            if received > self.max_bytes:
                await _too_large(scope, send, self.max_bytes)
                return
            chunks.append(body)
            more_body = message.get("more_body", False)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


async def _too_large(scope: Scope, send: Send, limit: int) -> None:
    response = _error_response(
        413, "payload_too_large", f"Request bodies are limited to {limit} bytes.", {}
    )
    await response(scope, _empty_receive, send)


async def _empty_receive() -> Message:
    return {"type": "http.disconnect"}


def _error_response(
    status: int,
    code: str,
    message: str,
    details: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    request_id = request_id_var.get()
    body = {
        "error": {"code": code, "message": message, "request_id": request_id, "details": details}
    }
    out_headers = dict(headers or {})
    if request_id:
        out_headers["X-Request-ID"] = request_id
    return JSONResponse(body, status_code=status, headers=out_headers)


def _container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def get_principal(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> Principal:
    return _container(request).authenticator.authenticate(authorization)


def idempotency_key(
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            description="Optional client key (8-128 chars of A-Z a-z 0-9 . _ : -). Repeating a "
            "request with the same key and body returns the original result; a different "
            "body returns 409.",
        ),
    ] = None,
) -> str | None:
    if idempotency_key is not None and not _IDEMPOTENCY.fullmatch(idempotency_key):
        raise InvalidInput("Idempotency-Key must be 8-128 characters of A-Za-z0-9._:-")
    return idempotency_key


PrincipalDep = Annotated[Principal, Depends(get_principal)]
IdempotencyDep = Annotated[str | None, Depends(idempotency_key)]
DeploymentId = Annotated[str, Path(pattern=DEPLOYMENT_ID_PATTERN)]
JobId = Annotated[str, Path(pattern=JOB_ID_PATTERN)]

ERRORS: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 413, 422, 429, 503)
}


def _accepted(status: int, body: dict[str, Any]) -> JSONResponse:
    return JSONResponse(AcceptedResponse(**body).model_dump(mode="json"), status_code=status)


SessionId = Annotated[str, Path(pattern=r"^chat_[0-9a-f]{32}$")]


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/me", tags=["users"])
    def profile(principal: PrincipalDep, request: Request) -> dict[str, Any]:
        return CatalogService(_container(request).db).profile(principal)

    @router.patch("/me", tags=["users"])
    def update_profile(
        body: ProfileUpdate, principal: PrincipalDep, request: Request
    ) -> dict[str, Any]:
        return CatalogService(_container(request).db).profile(
            principal, body.model_dump(exclude_none=True)
        )

    @router.get("/resources", tags=["resources"])
    def resources(
        principal: PrincipalDep,
        request: Request,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = Query(None, max_length=512),
    ) -> dict[str, Any]:
        return CatalogService(_container(request).db).resources(principal, limit, cursor)

    @router.get("/resources/{resource_id}", tags=["resources"])
    def resource(resource_id: UUID, principal: PrincipalDep, request: Request) -> dict[str, Any]:
        return CatalogService(_container(request).db).resource(principal, str(resource_id))

    @router.post("/chats", tags=["chats"], status_code=201)
    def create_chat(body: ChatTitle, principal: PrincipalDep, request: Request) -> dict[str, Any]:
        return CatalogService(_container(request).db).create_chat(principal, body.title)

    @router.get("/chats", tags=["chats"])
    def chats(
        principal: PrincipalDep,
        request: Request,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = Query(None, max_length=512),
    ) -> dict[str, Any]:
        return CatalogService(_container(request).db).chats(principal, limit, cursor)

    @router.patch("/chats/{chat_id}", tags=["chats"])
    def chat_title(
        chat_id: SessionId, body: ChatTitle, principal: PrincipalDep, request: Request
    ) -> dict[str, Any]:
        return CatalogService(_container(request).db).title(principal, chat_id, body.title)

    @router.get("/chats/{chat_id}/messages", tags=["chats"])
    def messages(
        chat_id: SessionId,
        principal: PrincipalDep,
        request: Request,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = Query(None, max_length=512),
    ) -> dict[str, Any]:
        return CatalogService(_container(request).db).messages(principal, chat_id, limit, cursor)

    @router.post(
        "/agent/messages",
        response_model=AgentReply,
        responses=ERRORS,
        tags=["agent"],
        summary="Chat with the configuration assistant",
    )
    async def agent_message(
        body: AgentMessageRequest, principal: PrincipalDep, key: IdempotencyDep, request: Request
    ) -> AgentReply:
        return await _container(request).agent.handle(principal, body, request_id_var.get(), key)

    @router.post(
        "/deployments",
        status_code=202,
        response_model=AcceptedResponse,
        responses=ERRORS,
        tags=["deployments"],
        summary="Request a VM: reserves quota and queues a plan preview",
    )
    def create_deployment(
        body: DeploymentRequest, principal: PrincipalDep, key: IdempotencyDep, request: Request
    ) -> JSONResponse:
        status, response = _container(request).deployments.create_deployment(
            principal, body, key, request_id_var.get()
        )
        return _accepted(status, response)

    @router.get(
        "/deployments", response_model=DeploymentList, responses=ERRORS, tags=["deployments"]
    )
    def list_deployments(
        principal: PrincipalDep,
        request: Request,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = Query(None, max_length=512),
    ) -> DeploymentList:
        items, next_cursor = _container(request).deployments.deployment_page(
            principal, limit, cursor
        )
        return DeploymentList(deployments=items, next_cursor=next_cursor)

    @router.get(
        "/deployments/{deployment_id}",
        response_model=DeploymentDetail,
        responses=ERRORS,
        tags=["deployments"],
    )
    def get_deployment(
        deployment_id: DeploymentId, principal: PrincipalDep, request: Request
    ) -> DeploymentDetail:
        return _container(request).deployments.get_deployment(principal, deployment_id)

    @router.post(
        "/deployments/{deployment_id}/plan",
        status_code=202,
        response_model=AcceptedResponse,
        responses=ERRORS,
        tags=["deployments"],
        summary="Refresh the create/repair preview; invalidates any earlier plan",
    )
    def refresh_plan(
        deployment_id: DeploymentId,
        principal: PrincipalDep,
        key: IdempotencyDep,
        request: Request,
    ) -> JSONResponse:
        status, response = _container(request).deployments.request_plan(
            principal, deployment_id, "create", key, request_id_var.get()
        )
        return _accepted(status, response)

    @router.post(
        "/deployments/{deployment_id}/deletion-plan",
        status_code=202,
        response_model=AcceptedResponse,
        responses=ERRORS,
        tags=["deployments"],
        summary="Preview deletion (irreversible data loss) for explicit approval",
    )
    def deletion_plan(
        deployment_id: DeploymentId,
        principal: PrincipalDep,
        key: IdempotencyDep,
        request: Request,
    ) -> JSONResponse:
        status, response = _container(request).deployments.request_plan(
            principal, deployment_id, "destroy", key, request_id_var.get()
        )
        return _accepted(status, response)

    @router.post(
        "/deployments/{deployment_id}/approve",
        status_code=202,
        response_model=AcceptedResponse,
        responses=ERRORS,
        tags=["deployments"],
        summary="Approve the exact displayed plan (ID + SHA-256) and queue apply",
    )
    def approve(
        deployment_id: DeploymentId,
        body: ApprovalRequest,
        principal: PrincipalDep,
        key: IdempotencyDep,
        request: Request,
    ) -> JSONResponse:
        status, response = _container(request).deployments.approve(
            principal, deployment_id, body, key, request_id_var.get()
        )
        return _accepted(status, response)

    @router.get("/jobs/{job_id}", response_model=JobSummary, responses=ERRORS, tags=["jobs"])
    def get_job(job_id: JobId, principal: PrincipalDep, request: Request) -> JobSummary:
        return _container(request).deployments.get_job(principal, job_id)

    @router.get("/healthz", tags=["ops"], include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/readyz", tags=["ops"], include_in_schema=False)
    def readyz(request: Request) -> JSONResponse:
        container = _container(request)
        settings = container.settings
        checks: dict[str, Any] = {"provisioner": settings.provisioner.value}
        ready = True
        try:
            version = container.db.schema_version()
            checks["schema_version"] = version
            ready = version == LATEST_SCHEMA_VERSION
            with container.db.read() as conn:
                row = conn.execute(
                    "SELECT heartbeat_at, healthy, checks_json FROM worker_heartbeats "
                    "ORDER BY heartbeat_at DESC LIMIT 1"
                ).fetchone()
            last = row["heartbeat_at"] if row else None
            recent = bool(
                last
                and (utcnow() - from_db_time(last)).total_seconds() < settings.worker_stale_seconds
            )
            healthy = bool(row and row["healthy"])
            checks.update(
                worker_last_heartbeat=last.isoformat() if last else None,
                worker_recent=recent,
                worker_self_check_ok=healthy,
            )
            if row and not healthy:
                problem = json.loads(row["checks_json"] or "{}")
                checks["worker_self_check"] = {
                    k: problem.get(k) for k in ("code", "message") if k in problem
                }
            if settings.provisioner is not ProvisionerKind.DISABLED:
                # Jobs only progress with a live worker whose self-check passed.
                ready = ready and recent and healthy
        except Exception:
            log.warning("readiness check failed", exc_info=True)
            ready = False
        return JSONResponse({"ready": ready, "checks": checks}, status_code=200 if ready else 503)

    return router


def create_app(settings: Settings, container: Container | None = None) -> FastAPI:
    container = container or build_container(settings)
    container.db.require_current_schema()
    app = FastAPI(
        title="UnitCompute API",
        version="0.1.0",
        description=(
            "Configure -> preview -> explicitly approve -> launch -> inspect -> explicitly "
            "delete a single Linux EC2 VM per user. All routes require a bearer token. "
            "Mutations accept an optional `Idempotency-Key` header."
        ),
    )
    app.state.container = container

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Any]]
    ) -> Any:
        request_id = uuid.uuid4().hex
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(AppError)
    async def app_error(_: Request, exc: AppError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        return _error_response(exc.status_code, exc.code, exc.message, exc.details, headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [
            {
                "loc": [str(p) for p in error.get("loc", ())],
                "msg": error.get("msg", ""),
                "type": error.get("type", ""),
            }
            for error in exc.errors()[:20]
        ]
        return _error_response(
            422, "invalid_input", "The request is invalid.", {"problems": problems}
        )

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error", exc_info=exc)
        return _error_response(500, "internal_error", "An internal error occurred.", {})

    app.include_router(build_router())
    app.add_middleware(BodySizeLimit, max_bytes=settings.max_request_bytes)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
            expose_headers=["X-Request-ID"],
            max_age=600,
        )
    return app
