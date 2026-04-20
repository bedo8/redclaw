"""Claude API Adapter — direct testing of Claude-based agents via the Anthropic API."""

from __future__ import annotations

import os
from typing import Any

from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse, register_adapter
from redclaw.config import TargetConfig


@register_adapter("claude_api")
class ClaudeAPIAdapter(AgentAdapter):
    """Adapter for testing agents built on the Claude API.

    Connects directly to the Claude API (via AI endpoint) and
    sends adversarial messages. This adapter is useful for testing:
    - System prompt resilience
    - Tool use security
    - Context window manipulation

    The adapter maintains conversation history for multi-turn attacks.
    """

    def __init__(
        self,
        config: TargetConfig,
        system_prompt: str = "",
        model: str = "claude-sonnet-4-6",
        tools: list[dict] | None = None,
    ) -> None:
        self._config = config
        self._system_prompt = system_prompt
        self._model = model
        self._tools = tools or []
        self._client: Any = None
        self._conversation: list[dict] = []

    @property
    def adapter_type(self) -> str:
        return "claude_api"

    async def connect(self) -> None:
        """Initialize the Anthropic client."""
        try:
            from anthropic import AsyncAnthropic
        except ImportError as err:
            raise ImportError("anthropic package required: pip install anthropic") from err

        base_url = self._config.url or os.environ.get(
            "LLM_PROXY_ENDPOINT",
            os.environ.get("ANTHROPIC_BASE_URL", ""),
        )
        api_key = self._config.auth_token or os.environ.get(
            "LLM_PROXY_API_KEY", os.environ.get("ANTHROPIC_API_KEY", "")
        )

        self._client = AsyncAnthropic(
            base_url=base_url,
            api_key=api_key,
        )
        self._conversation = []
        logger.info(f"Connected to Claude API at {base_url}")

    async def disconnect(self) -> None:
        self._client = None
        self._conversation = []

    async def send_message(self, message: str) -> AgentResponse:
        """Send message to Claude and get response."""
        if not self._client:
            raise RuntimeError("Adapter not connected.")

        self._conversation.append({"role": "user", "content": message})

        try:
            kwargs: dict[str, Any] = {
                "model": self._model,
                "max_tokens": 1024,
                "messages": self._conversation,
            }

            if self._system_prompt:
                kwargs["system"] = self._system_prompt

            if self._tools:
                kwargs["tools"] = self._tools

            response = await self._client.messages.create(**kwargs)

            # Extract text and tool calls
            text_parts: list[str] = []
            tool_calls: list[dict] = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_calls.append(
                        {
                            "id": block.id,
                            "name": block.name,
                            "arguments": block.input,
                        }
                    )

            text = "\n".join(text_parts)

            # Add assistant response to conversation
            self._conversation.append({"role": "assistant", "content": response.content})

            return AgentResponse(
                text=text,
                tool_calls=tool_calls,
                raw={
                    "id": response.id,
                    "model": response.model,
                    "stop_reason": response.stop_reason,
                    "usage": {
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                    },
                },
            )

        except Exception as exc:
            logger.error(f"Claude API error: {exc}")
            # Remove the failed user message from conversation
            self._conversation.pop()
            return AgentResponse(error=str(exc))

    async def send_multi_turn(self, messages: list[str]) -> list[AgentResponse]:
        """Send multiple messages maintaining conversation context."""
        responses: list[AgentResponse] = []
        for msg in messages:
            resp = await self.send_message(msg)
            responses.append(resp)
            if not resp.ok:
                break
        return responses

    async def get_available_tools(self) -> list[dict[str, Any]]:
        """Return the tools configured for this Claude agent."""
        return self._tools

    def set_system_prompt(self, prompt: str) -> None:
        """Set the system prompt for the agent under test."""
        self._system_prompt = prompt

    def set_tools(self, tools: list[dict]) -> None:
        """Set the tools available to the agent under test."""
        self._tools = tools

    def reset_conversation(self) -> None:
        """Clear conversation history for a fresh start."""
        self._conversation = []
