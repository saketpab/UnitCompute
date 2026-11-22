"""HTTP entry point for UniCompute."""

from os import getenv
from threading import Lock
from typing import Annotated, Literal, Protocol
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, StringConstraints

from agent.models import VMPlan

# Allow browser requests from the frontend origins configured for this server.
def configure_cors(application: FastAPI) -> None:
    origins = [
        origin.strip()
        for origin in getenv("UNICOMPUTE_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]
    if origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
        )


app = FastAPI(title="UniCompute")
configure_cors(app)
graph_lock = Lock()
# Requests for the same chat share a lock while checking and resuming a checkpoint.
chat_locks = tuple(Lock() for _ in range(64))
MessageText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


# Validate the initial prompt that starts a chat.
class ChatRequest(BaseModel):
    message: MessageText


# Require each follow-up to identify the question or plan it answers.
class ChatAction(BaseModel):
    interrupt_id: str


# Validate the user's answer to a clarification question.
class Clarify(ChatAction):
    action: Literal["clarify"]
    message: MessageText


# Validate the changes the user wants to make to a proposed plan.
class RevisePlan(ChatAction):
    action: Literal["change"]
    changes: MessageText


# Represent the user's approval of the pending plan.
class ApprovePlan(ChatAction):
    action: Literal["approve"]


# Include the conversation ID in every agent reply.
class ChatReply(BaseModel):
    chat_id: UUID


# Tell the frontend which detail the agent needs and what question to display.
class MissingDetail(ChatReply):
    type: Literal["missing_detail"]
    interrupt_id: str
    field: str
    question: str


# Return the proposed plan and its approval question for the frontend to display.
class PlanReview(ChatReply):
    type: Literal["approval"]
    interrupt_id: str
    question: str
    plan: dict[str, str | int | None]


# Return a plain text response from the agent.
class AgentMessage(ChatReply):
    type: Literal["message"]
    message: str


# Return the plan after the user approves it.
class ApprovedPlan(ChatReply):
    type: Literal["approved"]
    plan: dict[str, str | int | None]
    launch_status: Literal["not_configured", "accepted"] = "not_configured"
    resource_id: UUID | None = None


# The frontend uses "type" to choose between a question, plan review, and message.
InitialReply = Annotated[
    MissingDetail | PlanReview | AgentMessage, Field(discriminator="type")
]
FollowUpReply = Annotated[
    MissingDetail | PlanReview | AgentMessage | ApprovedPlan,
    Field(discriminator="type"),
]

InstanceAction = Literal["start", "stop", "reboot", "terminate"]


# Define the launch operations FastAPI needs from the AWS and database integration.
class ProvisioningService(Protocol):
    # Check that the caller owns the chat before approval can trigger a launch.
    def owns_chat(self, *, chat_id: UUID) -> bool: ...

    # Record the approved plan, start provisioning, and return its UniCompute resource ID.
    def submit_launch(self, *, chat_id: UUID, plan: VMPlan, request_id: str) -> UUID: ...


# Leave approval available for local demos until the real service is wired in.
def get_provisioning_service() -> ProvisioningService | None:
    return None


ProvisioningServiceDependency = Annotated[
    ProvisioningService | None, Depends(get_provisioning_service)
]


# Represent one instance in the dashboard using its UniCompute resource ID.
class InstanceSummary(BaseModel):
    id: UUID
    name: str
    region: str
    status: str


# Define the lifecycle action requested by the dashboard.
class InstanceActionRequest(BaseModel):
    action: InstanceAction


# Define what the REST routes need from a service scoped to the current user.
class InstanceService(Protocol):
    # Return the instances visible to the caller.
    def list_instances(self) -> list[InstanceSummary]: ...

    # Submit an action and return False if the instance is unavailable to the caller.
    def submit_action(self, instance_id: UUID, action: InstanceAction) -> bool: ...


# Provide the service through FastAPI dependency injection once it is wired up.
def get_instance_service() -> InstanceService:
    raise HTTPException(status_code=503, detail="Instance management is not configured.")


InstanceServiceDependency = Annotated[InstanceService, Depends(get_instance_service)]


@app.get("/api/instances", responses={503: {"description": "Instance service unavailable"}})
# Return the instance summaries used by the dashboard.
def list_instances(service: InstanceServiceDependency) -> list[InstanceSummary]:
    return service.list_instances()


@app.post(
    "/api/instances/{instance_id}/actions",
    status_code=202,
    response_class=Response,
    responses={
        404: {"description": "Instance not found"},
        503: {"description": "Instance service unavailable"},
    },
)
# Submit a lifecycle action and acknowledge it once the service accepts it.
def perform_instance_action(
    instance_id: UUID,
    request: InstanceActionRequest,
    service: InstanceServiceDependency,
) -> Response:
    if not service.submit_action(instance_id, request.action):
        raise HTTPException(status_code=404, detail="Instance not found.")
    return Response(status_code=202)


# Load and reuse one agent graph per server process.
def get_graph():
    """Initialize the agent once per server process, on the first chat request."""
    # Lazy loading lets health checks and API docs work without Gemini credentials.
    from run_agent import build_graph

    with graph_lock:
        if not hasattr(app.state, "graph"):
            try:
                app.state.graph = build_graph()
            except KeyError as exc:
                if exc.args != ("GOOGLE_API_KEY",):
                    raise
                raise HTTPException(
                    status_code=503, detail="The AI agent is not configured."
                ) from exc
        return app.state.graph


@app.get("/health")
# Return a simple response callers can use to check that the API is running.
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/chats", status_code=201, response_model=InitialReply)
# Start a new agent conversation and return its first reply.
def create_chat(request: ChatRequest) -> dict:
    # LangGraph uses the chat ID to keep each conversation's checkpoints separate.
    chat_id = uuid4()
    result = get_graph().invoke(
        {"user_request": request.message},
        {"configurable": {"thread_id": str(chat_id)}},
    )
    return format_reply(chat_id, result)


# Convert a LangGraph result into the JSON response the frontend expects.
def format_reply(chat_id: UUID, result: dict) -> dict:
    if pending := result.get("__interrupt__"):
        current = pending[0]
        return {"chat_id": chat_id, "interrupt_id": current.id, **current.value}
    if result.get("approval_status") == "approved":
        return {"chat_id": chat_id, "type": "approved", "plan": result["plan_review"]}
    if message := result.get("response"):
        return {"chat_id": chat_id, "type": "message", "message": message}
    raise HTTPException(status_code=502, detail="The AI agent returned no reply.")


@app.post("/api/chats/{chat_id}/messages", response_model=FollowUpReply)
# Validate the reply against the pending question or plan and resume the conversation.
def continue_chat(
    chat_id: UUID,
    request: Annotated[Clarify | RevisePlan | ApprovePlan, Field(discriminator="action")],
    provisioning: ProvisioningServiceDependency,
) -> dict:
    from langgraph.types import Command

    if (
        isinstance(request, ApprovePlan)
        and provisioning is not None
        and not provisioning.owns_chat(chat_id=chat_id)
    ):
        raise HTTPException(status_code=404, detail="Chat not found.")

    graph = get_graph()
    config = {"configurable": {"thread_id": str(chat_id)}}
    with chat_locks[chat_id.int % len(chat_locks)]:
        snapshot = graph.get_state(config)
        if not snapshot.values:
            raise HTTPException(status_code=404, detail="Chat not found.")

        # Match the pending interrupt so an old form cannot approve a revised plan.
        pending = [interrupt for task in snapshot.tasks for interrupt in task.interrupts]
        if not pending or pending[0].id != request.interrupt_id:
            raise HTTPException(status_code=409, detail="This reply is no longer current.")

        if pending[0].value["type"] == "missing_detail" and isinstance(request, Clarify):
            answer = request.message
        elif pending[0].value["type"] == "approval" and not isinstance(request, Clarify):
            answer = request.model_dump(exclude={"interrupt_id"})
        else:
            raise HTTPException(status_code=409, detail="That action does not match the current question.")

        # Resume the existing LangGraph thread from its checkpoint with this reply.
        result = graph.invoke(Command(resume=answer), config)
        reply = format_reply(chat_id, result)
        if isinstance(request, ApprovePlan) and reply["type"] == "approved" and provisioning is not None:
            # One approved plan can launch per chat, so the chat ID is the stable request ID.
            resource_id = provisioning.submit_launch(
                chat_id=chat_id, plan=result["vm_plan"], request_id=chat_id.hex
            )
            reply.update(launch_status="accepted", resource_id=resource_id)
        return reply
