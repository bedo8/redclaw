"""Claude API adapter — test a Claude-based agent definition directly.

The "agent" is a model + system prompt (+ optional tool definitions) that
RedClaw drives through the Anthropic Messages API. Credentials and the
endpoint come from the standard environment variables:

* ``ANTHROPIC_API_KEY`` (or ``--auth-token`` / ``REDCLAW_AUTH_TOKEN``)
* ``ANTHROPIC_BASE_URL`` for a gateway or proxy (or a non-empty ``--target``)

The model defaults to ``REDCLAW_CLAUDE_MODEL`` (``claude-sonnet-5-5`` unless
overridden); ``--model`` accepts a model name or the aliases ``default``,
``heavy`` and ``fast``.
"""

from __future__ import annotations

import copy
from typing import Any

from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse, register_adapter
from redclaw.config import RedClawSettings, TargetConfig


@register_adapter("claude_api")
class ClaudeAPIAdapter(AgentAdapter):
    """Adapter for agents built directly on the Anthropic Messages API."""

    def __init__(
        self,
        config: TargetConfig,
        system_prompt: str | None = None,
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 1024,
        settings: RedClawSettings | None = None,
        client: Any = None,
    ) -> None:
        self._config = config
        self._settings = settings or RedClawSettings()
        self._system_prompt = system_prompt if system_prompt is not None else config.system_prompt
        self._model = self._settings.resolved_claude_model(model or config.model)
        self._tools = tools or []
        self._max_tokens = max_tokens
        self._client: Any = client
        self._owns_client = client is None
        self._conversation: list[dict[str, Any]] = []

    @property
    def adapter_type(self) -> str:
        return "claude_api"

    @property
    def model(self) -> str:
        return self._model

    @property
    def supports_concurrency(self) -> bool:
        return True

    def fork(self) -> ClaudeAPIAdapter:
        clone = copy.copy(self)
        clone._conversation = []
        return clone

    async def connect(self) -> None:
        """Create the Anthropic client."""
        if self._client is not None:
            return
        try:
            from anthropic import AsyncAnthropic
        except ImportError as err:  # pragma: no cover - anthropic is a core dependency
            raise ImportError("The 'anthropic' package is required") from err

        api_key = (
            self._config.auth_token.get_secret_value()
            if self._config.auth_token
            else (
                self._settings.anthropic_api_key.get_secret_value()
                if self._settings.anthropic_api_key
                else None
            )
        )
        if not api_key:
            raise RuntimeError(
                "No API key for the claude_api adapter: set ANTHROPIC_API_KEY or pass --auth-token"
            )
        base_url = self._config.url or self._settings.anthropic_base_url or None

        self._client = AsyncAnthropic(
            api_key=api_key,
            base_url=base_url,
            timeout=float(self._config.timeout_seconds),
            max_retries=2,
        )
        self._owns_client = True
        self._conversation = []
        logger.info(f"Claude API adapter ready (model {self._model}, base {base_url or 'default'})")

    async def disconnect(self) -> None:
        client, self._client = self._client, None
        self._conversation = []
        if client is not None and self._owns_client and hasattr(client, "close"):
            await client.close()

    async def send_message(self, message: str) -> AgentResponse:
        """Send one user turn and return the assistant's reply."""
        if not self._client:
            raise RuntimeError("Adapter not connected.")

        messages = [*self._conversation, {"role": "user", "content": message}]
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }
        if self._system_prompt:
            kwargs["system"] = self._system_prompt
        if self._tools:
            kwargs["tools"] = self._tools

        try:
            response = await self._client.messages.create(**kwargs)
        except Exception as exc:
            logger.warning(f"Claude API error: {exc}")
            status = getattr(exc, "status_code", 0) or 0
            return AgentResponse(error=f"{type(exc).__name__}: {exc}", status_code=status)

        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name, "arguments": block.input})

        assistant_content = [block.model_dump(exclude_none=True) for block in response.content]
        self._conversation = [*messages, {"role": "assistant", "content": assistant_content}]
        if tool_calls:
            # The agent asked to run tools; RedClaw does not execute them, but the
            # conversation must stay valid for the next turn.
            self._conversation.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tc["id"],
                            "content": "Tool execution is disabled in this test harness.",
                            "is_error": True,
                        }
                        for tc in tool_calls
                    ],
                }
            )

        usage = getattr(response, "usage", None)
        return AgentResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            raw={
                "id": response.id,
                "model": response.model,
                "stop_reason": response.stop_reason,
                "usage": {
                    "input_tokens": getattr(usage, "input_tokens", None),
                    "output_tokens": getattr(usage, "output_tokens", None),
                },
            },
        )

    async def send_multi_turn(self, messages: list[str]) -> list[AgentResponse]:
        """Send several turns in one conversation, stopping at the first error."""
        responses: list[AgentResponse] = []
        for msg in messages:
            resp = await self.send_message(msg)
            responses.append(resp)
            if not resp.ok:
                break
        return responses

    async def get_available_tools(self) -> list[dict[str, Any]]:
        return self._tools

    def set_system_prompt(self, prompt: str) -> None:
        self._system_prompt = prompt

    def set_tools(self, tools: list[dict[str, Any]]) -> None:
        self._tools = tools

    def reset_conversation(self) -> None:
        self._conversation = []
