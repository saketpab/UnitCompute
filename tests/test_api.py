"""Exercise the HTTP chat contract with real LangGraph checkpoints."""

from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api
from agent.agent_graph import build_agent_graph
from agent.checkpointing import create_development_checkpointer
from agent.models import AgentIntent, VMPlan, VMRequest
from agent.planner import PlanBuilder
from agent.requirements import RequirementChecker
from agent.workflow import build_create_ec2_workflow


# Check that browser preflight permits configured origins and rejects an unrelated origin.
def test_cors_preflight(monkeypatch):
    frontend = "http://localhost:3000"
    other_frontend = "http://localhost:5173"
    monkeypatch.setenv("UNICOMPUTE_ALLOWED_ORIGINS", f"{frontend}, {other_frontend}")
    application = FastAPI()
    api.configure_cors(application)
    headers = {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }

    with TestClient(application) as client:
        for origin in (frontend, other_frontend):
            response = client.options("/api/chats", headers={**headers, "Origin": origin})
            assert response.status_code == 200
            assert response.headers["Access-Control-Allow-Origin"] == origin

        response = client.options(
            "/api/chats", headers={**headers, "Origin": "http://localhost:9000"}
        )
        assert response.status_code == 400
        assert "Access-Control-Allow-Origin" not in response.headers


# Route the test prompt to the real EC2 planning workflow without Gemini.
class CreateRouter:
    # Return the create intent for the prompt this test sends.
    def route(self, message: str) -> AgentIntent:
        assert message == "I need a VM for class."
        return AgentIntent(action="create", resource="ec2")


# Supply predictable model outputs for the prompt, clarification, and revision.
class CannedTranslator:
    # Look up the structured VM request that corresponds to this turn.
    def translate(self, message: str) -> VMRequest:
        return {
            "I need a VM for class.": VMRequest(compute_size="small", region="us-east-2"),
            "Ubuntu": VMRequest(operating_system="ubuntu"),
            "Increase the disk to 40 GB.": VMRequest(disk_gb=40),
        }[message]


# Record submitted plans without using PostgreSQL or AWS.
class FakeProvisioningService:
    # Start with access allowed and no recorded submissions.
    def __init__(self):
        self.allowed = True
        self.submissions = []
        self.resource_id = UUID("498b1ce6-a1d0-471b-bbca-f6f6e1c3e2df")

    # Simulate the ownership lookup provided by the database integration.
    def owns_chat(self, *, chat_id: UUID) -> bool:
        return self.allowed

    # Record the exact plan and request ID sent by FastAPI.
    def submit_launch(self, *, chat_id: UUID, plan: VMPlan, request_id: str) -> UUID:
        self.submissions.append((chat_id, plan, request_id))
        return self.resource_id


@pytest.mark.parametrize("launch_enabled", [False, True])
# Verify the full chat workflow both with and without a configured provisioning service.
def test_chat_clarify_revise_and_approve(monkeypatch, launch_enabled):
    workflow = build_create_ec2_workflow(CannedTranslator(), RequirementChecker(), PlanBuilder())
    graph = build_agent_graph(
        CreateRouter(), workflow, checkpointer=create_development_checkpointer()
    )
    monkeypatch.setattr(api, "get_graph", lambda: graph)
    provisioning = FakeProvisioningService()
    if launch_enabled:
        monkeypatch.setitem(
            api.app.dependency_overrides, api.get_provisioning_service, lambda: provisioning
        )

    with TestClient(api.app) as client:
        response = client.post("/api/chats", json={"message": "I need a VM for class."})
        assert response.status_code == 201, response.text
        question = response.json()
        assert question["type"] == "missing_detail"
        assert question["field"] == "operating_system"
        path = f"/api/chats/{question['chat_id']}/messages"

        response = client.post(path, json={
            "action": "clarify",
            "interrupt_id": question["interrupt_id"],
            "message": "Ubuntu",
        })
        assert response.status_code == 200, response.text
        review = response.json()
        assert review["type"] == "approval"
        assert review["plan"]["operating_system"] == "ubuntu"
        assert review["plan"]["disk_gb"] == 30

        response = client.post(path, json={
            "action": "change",
            "interrupt_id": review["interrupt_id"],
            "changes": "Increase the disk to 40 GB.",
        })
        assert response.status_code == 200, response.text
        revised = response.json()
        assert revised["type"] == "approval"
        assert revised["plan"]["disk_gb"] == 40

        response = client.post(path, json={
            "action": "approve", "interrupt_id": review["interrupt_id"],
        })
        assert response.status_code == 409, response.text
        assert provisioning.submissions == []

        approval = {"action": "approve", "interrupt_id": revised["interrupt_id"]}
        if launch_enabled:
            provisioning.allowed = False
            assert client.post(path, json=approval).status_code == 404
            assert provisioning.submissions == []
            provisioning.allowed = True

        response = client.post(path, json=approval)
        assert response.status_code == 200, response.text
        assert response.json() == {
            "chat_id": question["chat_id"],
            "type": "approved",
            "plan": revised["plan"],
            "launch_status": "accepted" if launch_enabled else "not_configured",
            "resource_id": str(provisioning.resource_id) if launch_enabled else None,
        }
        assert client.post(path, json=approval).status_code == 409
        if launch_enabled:
            chat_id = UUID(question["chat_id"])
            expected_plan = PlanBuilder().build(VMRequest(
                operating_system="ubuntu", compute_size="small", region="us-east-2", disk_gb=40
            ))
            assert provisioning.submissions == [(chat_id, expected_plan, chat_id.hex)]
        else:
            assert provisioning.submissions == []


# Provide one dashboard instance and record accepted requests without making AWS calls.
class FakeInstanceService:
    # Set up the dashboard entry and the list of submitted actions.
    def __init__(self):
        self.instance = api.InstanceSummary(
            id=UUID("483039ee-356f-4e40-a432-dda7dc92848f"),
            name="Class VM",
            region="us-east-2",
            status="running",
        )
        self.actions = []

    # Return the fake instance to the dashboard.
    def list_instances(self):
        return [self.instance]

    # Accept actions for the fake instance and reject unknown IDs.
    def submit_action(self, instance_id, action):
        if instance_id != self.instance.id:
            return False
        self.actions.append(action)
        return True


# Check that the routes report service unavailability until an adapter is configured.
def test_instance_service_unavailable():
    with TestClient(api.app) as client:
        assert client.get("/api/instances").status_code == 503
        response = client.post(
            "/api/instances/483039ee-356f-4e40-a432-dda7dc92848f/actions",
            json={"action": "stop"},
        )
        assert response.status_code == 503


# Check listing, action dispatch, and request validation through the REST routes.
def test_instance_routes_with_service(monkeypatch):
    service = FakeInstanceService()
    monkeypatch.setitem(api.app.dependency_overrides, api.get_instance_service, lambda: service)

    with TestClient(api.app) as client:
        response = client.get("/api/instances")
        assert response.status_code == 200
        assert response.json() == [service.instance.model_dump(mode="json")]

        path = f"/api/instances/{service.instance.id}/actions"
        actions = ["start", "stop", "reboot", "terminate"]
        for action in actions:
            response = client.post(path, json={"action": action})
            assert response.status_code == 202
            assert response.content == b""

        assert client.post(path, json={"action": "unknown"}).status_code == 422
        assert client.post("/api/instances/invalid/actions", json={"action": "stop"}).status_code == 422
        response = client.post(
            "/api/instances/00000000-0000-0000-0000-000000000000/actions",
            json={"action": "stop"},
        )
        assert response.status_code == 404
        assert service.actions == actions
