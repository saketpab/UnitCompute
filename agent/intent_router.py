"""Classify a user's EC2 request before entering a workflow."""

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from agent.models import AgentIntent


class IntentRouter:
    """Uses any LangChain chat model to select an EC2 workflow."""

    SYSTEM_INSTRUCTION = (
        'Identify the requested EC2 action. '
        'Choose create, delete, list, or view_details. '
        'Set resource to exactly ec2, even if the user says server, VM, '
        'or EC2 server. '
        'Do not perform any cloud action.'
    )

    def __init__(self, chat_model: BaseChatModel) -> None:
        self._structured_model = chat_model.with_structured_output(AgentIntent)

    def route(self, user_request: str) -> AgentIntent:
        user_request = user_request.strip()
        if not user_request:
            raise ValueError('Please provide an EC2 request.')

        result = self._structured_model.invoke([
            SystemMessage(content=self.SYSTEM_INSTRUCTION),
            HumanMessage(content=user_request),
        ])
        return AgentIntent.model_validate(result)
