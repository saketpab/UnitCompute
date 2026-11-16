"""LangGraph workflow for collecting, reviewing, and approving an EC2 plan."""

from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from agent.models import VMPlan, VMRequest
from agent.planner import PlanBuilder
from agent.requirements import RequirementChecker, merge_request
from agent.translator import RequestTranslator


class ProvisioningState(TypedDict, total=False):
    user_request: str
    vm_request: VMRequest
    missing_fields: list[str]
    next_question: str | None
    vm_plan: VMPlan
    plan_review: dict[str, str | int | None]
    approval_status: Literal[
        'pending',
        'approved',
        'changes_requested',
    ] | None


def build_create_ec2_workflow(
    translator: RequestTranslator,
    checker: RequirementChecker,
    plan_builder: PlanBuilder,
):
    """Build a human-in-the-loop create-EC2 workflow; this never calls AWS."""

    def translate_and_merge(state: ProvisioningState) -> dict:
        update = translator.translate(state['user_request'])
        request = merge_request(state.get('vm_request'), update)
        return {
            'vm_request': request,
            'approval_status': None,
        }

    def check_requirements(state: ProvisioningState) -> dict:
        missing_fields = checker.missing_fields(state['vm_request'])
        next_question = (
            checker.next_question(missing_fields)
            if missing_fields
            else None
        )
        return {
            'missing_fields': missing_fields,
            'next_question': next_question,
        }

    def route_after_check(state: ProvisioningState) -> str:
        return 'collect_missing_detail' if state['missing_fields'] else 'build_plan'

    def collect_missing_detail(state: ProvisioningState) -> dict:
        """Pause until the user supplies the next required VM detail."""
        missing_fields = state['missing_fields']
        field_name = missing_fields[0]
        user_answer = interrupt({
            'type': 'missing_detail',
            'field': field_name,
            'question': state['next_question'],
        })

        update = translator.translate(user_answer)
        request = merge_request(state['vm_request'], update)
        return {
            'vm_request': request,
            'missing_fields': [],
            'next_question': None,
        }

    def build_plan(state: ProvisioningState) -> dict:
        return {'vm_plan': plan_builder.build(state['vm_request'])}

    def review_plan(state: ProvisioningState) -> dict:
        request = state['vm_request']
        plan = state['vm_plan']
        return {
            'plan_review': {
                'operating_system': request.operating_system,
                'compute_size': f'{request.compute_size} ({plan.instance_type})',
                'region': plan.region,
                'disk_gb': plan.disk_gb,
                'disk_gb_source': (
                    'user-selected'
                    if request.disk_gb is not None
                    else 'default'
                ),
                'name': plan.name,
                'name_source': (
                    'user-selected'
                    if request.name is not None
                    else 'generated'
                ),
                'purpose': plan.purpose,
                'subnet_id': plan.subnet_id,
                'security_group_id': plan.security_group_id,
            },
            'approval_status': 'pending',
        }

    def wait_for_approval(state: ProvisioningState) -> dict:
        """Pause until the user approves or revises the exact proposed plan."""
        decision = interrupt({
            'type': 'approval',
            'plan': state['plan_review'],
            'question': 'Do you approve this VM plan?',
        })

        if decision.get('action') == 'approve':
            return {'approval_status': 'approved'}

        if decision.get('action') == 'change':
            changes = decision.get('changes')
            if not isinstance(changes, str) or not changes.strip():
                raise ValueError('Please describe the requested VM plan changes.')

            update = translator.translate(changes)
            request = merge_request(state['vm_request'], update)
            return {
                'vm_request': request,
                'approval_status': 'changes_requested',
            }

        raise ValueError('Approval action must be approve or change.')

    def route_after_approval(state: ProvisioningState) -> str:
        if state['approval_status'] == 'approved':
            return 'approved'
        return 'check_requirements'

    graph = StateGraph(ProvisioningState)
    graph.add_node('translate_and_merge', translate_and_merge)
    graph.add_node('check_requirements', check_requirements)
    graph.add_node('collect_missing_detail', collect_missing_detail)
    graph.add_node('build_plan', build_plan)
    graph.add_node('review_plan', review_plan)
    graph.add_node('wait_for_approval', wait_for_approval)

    graph.add_edge(START, 'translate_and_merge')
    graph.add_edge('translate_and_merge', 'check_requirements')
    graph.add_conditional_edges(
        'check_requirements',
        route_after_check,
        {
            'collect_missing_detail': 'collect_missing_detail',
            'build_plan': 'build_plan',
        },
    )
    graph.add_edge('collect_missing_detail', 'check_requirements')
    graph.add_edge('build_plan', 'review_plan')
    graph.add_edge('review_plan', 'wait_for_approval')
    graph.add_conditional_edges(
        'wait_for_approval',
        route_after_approval,
        {
            'approved': END,
            'check_requirements': 'check_requirements',
        },
    )
    return graph.compile()
