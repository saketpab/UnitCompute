"""Top-level graph that routes requests to an EC2 workflow."""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from agent.intent_router import IntentRouter
from agent.models import AgentIntent
from agent.workflow import ProvisioningState


class AgentState(ProvisioningState, total=False):
    """Shared state for the intent router and a selected EC2 workflow."""

    intent: AgentIntent
    response: str | None


def build_agent_graph(
    intent_router: IntentRouter,
    create_ec2_workflow,
    checkpointer=None,
):
    """Build the top-level router without granting any AWS permissions."""

    def detect_intent(state: AgentState) -> dict:
        # Follow-up replies stay in their original workflow.
        if state.get('intent') is not None:
            return {}

        return {'intent': intent_router.route(state['user_request'])}

    def choose_workflow(state: AgentState) -> str:
        if state['intent'].action == 'create':
            return 'create'
        return 'not_implemented'

    def not_implemented(state: AgentState) -> dict:
        action = state['intent'].action.replace('_', ' ')
        return {
            'response': (
                f'The EC2 {action} workflow is not implemented yet. '
                'Only EC2 creation is currently available.'
            )
        }

    graph = StateGraph(AgentState)
    graph.add_node('detect_intent', detect_intent)
    graph.add_node('create', create_ec2_workflow)
    graph.add_node('not_implemented', not_implemented)

    graph.add_edge(START, 'detect_intent')
    graph.add_conditional_edges(
        'detect_intent',
        choose_workflow,
        {
            'create': 'create',
            'not_implemented': 'not_implemented',
        },
    )
    graph.add_edge('create', END)
    graph.add_edge('not_implemented', END)
    return graph.compile(checkpointer=checkpointer)
