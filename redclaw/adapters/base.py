"""Base adapter — abstract interface for communicating with target agents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentResponse:
    """Standardized response from any target agent."""

    text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    status_code: int = 200
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the response was successful."""
        return self.error is None and 200 <= self.status_code < 400


class AgentAdapter(ABC):
    """Abstract base class for agent communication adapters.

    Each adapter knows how to talk to a specific type of agent
    (HTTP API, MCP server, Claude API, etc.) and translates
    RedClaw's attack payloads into the right format.
    """

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Adapter identifier (e.g. 'http', 'mcp', 'claude_api')."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the target agent."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the target agent."""

    @abstractmethod
    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the agent and get its response.

        Args:
            message: The text payload to send.

        Returns:
            Standardized AgentResponse.
        """

    @abstractmethod
    async def get_available_tools(self) -> list[dict[str, Any]]:
        """List tools available to the target agent.

        Returns:
            List of tool descriptors (name, description, parameters).
        """

    async def send_multi_turn(self, messages: list[str]) -> list[AgentResponse]:
        """Send a sequence of messages (for multi-turn attacks).

        Default implementation sends sequentially. Adapters can override
        for session-aware implementations.

        Args:
            messages: Ordered list of messages.

        Returns:
            List of responses, one per message.
        """
        responses: list[AgentResponse] = []
        for msg in messages:
            resp = await self.send_message(msg)
            responses.append(resp)
        return responses

    async def inject_data(self, data: str, channel: str = "default") -> AgentResponse:
        """Inject data through a specific channel (e.g. document, API response).

        Default implementation falls back to send_message.
        Adapters should override for channel-specific injection.

        Args:
            data: The data payload to inject.
            channel: The injection channel identifier.

        Returns:
            AgentResponse from the injection.
        """
        return await self.send_message(data)

    async def __aenter__(self) -> AgentAdapter:
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.disconnect()
