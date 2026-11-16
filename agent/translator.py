"""Model-agnostic natural-language request translation."""

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from agent.models import VMRequest


class RequestTranslator:
    """Uses any LangChain chat model to return a validated VMRequest."""

    SYSTEM_INSTRUCTION = (
        'Extract the requested VM configuration. Use null for missing details.'
    )

    def __init__(self, chat_model: BaseChatModel) -> None:
        self._structured_model = chat_model.with_structured_output(VMRequest)

    def translate(self, user_request: str) -> VMRequest:
        user_request = user_request.strip()
        if not user_request:
            raise ValueError('Please provide a VM request.')

        result = self._structured_model.invoke([
            SystemMessage(content=self.SYSTEM_INSTRUCTION),
            HumanMessage(content=user_request),
        ])
        return VMRequest.model_validate(result)
