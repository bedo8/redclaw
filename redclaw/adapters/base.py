"""Base adapter — abstract interface for communicating with target agents."""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redclaw.config import TargetConfig


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

    @property
    def supports_concurrency(self) -> bool:
        """Whether several attacks may be in flight at once on this adapter.

        Adapters that multiplex one stateful connection (e.g. a single chat
        session) should leave this False; the engine then runs attacks one
        at a time regardless of a phase's ``max_concurrent``.
        """
        return False

    def fork(self) -> AgentAdapter:
        """Return a handle for one isolated attack (fresh conversation state).

        The fork shares the connection opened by :meth:`connect` but not the
        conversation history, so one attack's turns cannot leak into the
        next. The default returns ``self`` for adapters with no per-
        conversation state.
        """
        return self

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


# ---------------------------------------------------------------------------
# Adapter registry — decorator-based extension point
# ---------------------------------------------------------------------------
_ADAPTER_REGISTRY: dict[str, type[AgentAdapter]] = {}


def register_adapter(identifier: str) -> Callable[[type[AgentAdapter]], type[AgentAdapter]]:
    """Decorator: register an AgentAdapter subclass under `identifier`.

    Usage::

        @register_adapter("openclaw")
        class OpenClawAdapter(AgentAdapter):
            ...

    The identifier must match an `AdapterType` enum value so that campaign
    YAML can resolve the adapter at load time.
    """

    def decorator(cls: type[AgentAdapter]) -> type[AgentAdapter]:
        _ADAPTER_REGISTRY[identifier] = cls
        return cls

    return decorator


def get_adapter(identifier: str, config: TargetConfig, **kwargs: Any) -> AgentAdapter:
    """Instantiate a registered adapter by identifier.

    Only kwargs accepted by the adapter's __init__ are forwarded; this mirrors
    `redclaw.core.scheduler.get_module` so callers can pass a shared kwargs
    bag without per-adapter branching.
    """
    cls = _ADAPTER_REGISTRY.get(identifier)
    if cls is None:
        raise KeyError(
            f"Unknown adapter: {identifier}. Available: {sorted(_ADAPTER_REGISTRY.keys())}"
        )
    sig = inspect.signature(cls.__init__)
    valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
    # Subclasses accept (config, **kwargs); the ABC __init__ is zero-arg so
    # mypy can't infer the positional — construct via Any to avoid call-arg noise.
    factory: Any = cls
    return factory(config, **valid_kwargs)


def list_adapters() -> list[str]:
    """List identifiers of all registered adapters."""
    return sorted(_ADAPTER_REGISTRY.keys())
