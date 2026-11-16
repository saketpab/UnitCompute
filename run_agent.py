"""Run the UnitCompute Create-EC2 workflow from a terminal."""

from __future__ import annotations

import json
import os
from uuid import uuid4

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.types import Command

from agent.agent_graph import build_agent_graph
from agent.checkpointing import create_development_checkpointer
from agent.config import load_local_environment
from agent.intent_router import IntentRouter
from agent.planner import PlanBuilder
from agent.requirements import RequirementChecker
from agent.translator import RequestTranslator
from agent.workflow import build_create_ec2_workflow


def build_graph():
    """Create a locally runnable graph with in-memory checkpoints."""
    load_local_environment()
    chat_model = ChatGoogleGenerativeAI(
        model='gemini-2.5-flash',
        google_api_key=os.environ['GOOGLE_API_KEY'],
        temperature=0,
    )
    create_workflow = build_create_ec2_workflow(
        RequestTranslator(chat_model),
        RequirementChecker(),
        PlanBuilder(),
    )
    return build_agent_graph(
        IntentRouter(chat_model),
        create_workflow,
        checkpointer=create_development_checkpointer(),
    )


def interrupt_payload(result: dict) -> dict | None:
    """Return the current interrupt payload, if execution is paused."""
    pending = result.get('__interrupt__', ())
    return pending[0].value if pending else None


def main() -> None:
    graph = build_graph()
    conversation = {
        'configurable': {'thread_id': f'cli-{uuid4()}'},
    }

    user_request = input('What would you like to do with EC2? ').strip()
    result = graph.invoke({'user_request': user_request}, conversation)

    while payload := interrupt_payload(result):
        if payload['type'] == 'missing_detail':
            answer = input(f"{payload['question']} ").strip()
            result = graph.invoke(Command(resume=answer), conversation)
            continue

        if payload['type'] == 'approval':
            print('\nProposed VM plan:')
            print(json.dumps(payload['plan'], indent=2))
            choice = input('\nApprove this plan? [y/N] ').strip().lower()

            if choice in {'y', 'yes'}:
                decision = {'action': 'approve'}
            else:
                changes = input('Describe the changes you want: ').strip()
                decision = {'action': 'change', 'changes': changes}

            result = graph.invoke(Command(resume=decision), conversation)
            continue

        raise ValueError(f"Unknown interrupt type: {payload['type']}")

    if result.get('response'):
        print(f"\n{result['response']}")
        return

    if result.get('approval_status') == 'approved':
        approved_plan = result['vm_plan'].model_dump()
        print('\nApproved VM plan:')
        print(json.dumps(approved_plan, indent=2))
        print('\nNo AWS resource was created.')


if __name__ == '__main__':
    main()
