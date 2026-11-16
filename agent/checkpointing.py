"""Checkpoint configuration for local LangGraph development."""

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer


def create_development_checkpointer() -> InMemorySaver:
    """Create an in-memory saver that explicitly allows UnitCompute models."""
    serializer = JsonPlusSerializer(
        allowed_msgpack_modules=[
            ('agent.models', 'AgentIntent'),
            ('agent.models', 'VMRequest'),
            ('agent.models', 'VMPlan'),
        ]
    )
    return InMemorySaver(serde=serializer)
