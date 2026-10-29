"""Offline scripted chat model for tests and local development.

This is a FAKE model: it returns pre-scripted messages and never calls a provider. Its
replies are prefixed so they cannot be mistaken for real model output.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

FAKE_PREFIX = "[offline fake model]"
ScriptStep = AIMessage | Callable[[list[BaseMessage]], AIMessage]


class ScriptedChatModel(BaseChatModel):
    script: list[Any] = Field(default_factory=list)
    calls: int = 0

    @property
    def _llm_type(self) -> str:
        return "unitcompute-offline-fake"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ScriptedChatModel:
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        step: ScriptStep | None = self.script[self.calls] if self.calls < len(self.script) else None
        self.calls += 1
        if step is None:
            message = AIMessage(
                content=f"{FAKE_PREFIX} No live model is configured; use the REST workflow "
                "or configure UNITCOMPUTE_AGENT_MODEL."
            )
        else:
            message = step(messages) if callable(step) else step
        if isinstance(message.content, str) and not message.content.startswith(FAKE_PREFIX):
            message = message.model_copy(update={"content": f"{FAKE_PREFIX} {message.content}"})
        return ChatResult(generations=[ChatGeneration(message=message)])
