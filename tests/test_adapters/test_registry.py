"""Tests for the adapter registry — verifies external extension works without
modifying the core engine (Phase 2.1 architecture requirement)."""

from __future__ import annotations

from typing import Any

import pytest

from redclaw.adapters.base import (
    _ADAPTER_REGISTRY,
    AgentAdapter,
    AgentResponse,
    get_adapter,
    list_adapters,
    register_adapter,
)
from redclaw.config import AdapterType, TargetConfig


def test_builtin_adapters_registered() -> None:
    """Importing redclaw.adapters must register every AdapterType value."""
    # Force-load the package so decorators fire in a fresh pytest process.
    import redclaw.adapters  # noqa: F401

    registered = set(list_adapters())
    # Every enum value should resolve through the registry. Optional-dep
    # adapters are imported inside try/except in the package __init__, so if
    # the extra is installed they must be registered here.
    assert AdapterType.HTTP.value in registered
    assert AdapterType.MCP.value in registered


def test_get_adapter_http_returns_http_adapter_instance() -> None:
    import redclaw.adapters  # noqa: F401
    from redclaw.adapters.http_agent import HttpAgentAdapter

    target = TargetConfig(url="http://127.0.0.1:1", adapter=AdapterType.HTTP)
    adapter = get_adapter("http", target)
    assert isinstance(adapter, HttpAgentAdapter)
    assert adapter.adapter_type == "http"


def test_get_adapter_unknown_raises_keyerror() -> None:
    import redclaw.adapters  # noqa: F401

    target = TargetConfig(url="http://127.0.0.1:1")
    with pytest.raises(KeyError, match="Unknown adapter"):
        get_adapter("does_not_exist", target)


def test_register_adapter_decorator_adds_entry() -> None:
    """Proves you can add a new adapter via the decorator alone — no edits to
    engine.py or config.py required."""

    @register_adapter("_test_noop")
    class NoopAdapter(AgentAdapter):
        def __init__(self, config: TargetConfig) -> None:
            self._config = config

        @property
        def adapter_type(self) -> str:
            return "_test_noop"

        async def connect(self) -> None:
            return None

        async def disconnect(self) -> None:
            return None

        async def send_message(self, message: str) -> AgentResponse:
            return AgentResponse(text=f"echo:{message}")

        async def get_available_tools(self) -> list[dict[str, Any]]:
            return []

    try:
        assert "_test_noop" in _ADAPTER_REGISTRY
        target = TargetConfig(url="http://127.0.0.1:1")
        instance = get_adapter("_test_noop", target)
        assert isinstance(instance, NoopAdapter)
    finally:
        _ADAPTER_REGISTRY.pop("_test_noop", None)


def test_get_adapter_filters_extra_kwargs() -> None:
    """Adapters with narrow __init__ (e.g. HttpAgentAdapter) shouldn't break
    when callers pass kwargs intended for a different adapter."""
    import redclaw.adapters  # noqa: F401

    target = TargetConfig(url="http://127.0.0.1:1")
    # `model` is accepted by ClaudeAPIAdapter but not HttpAgentAdapter.
    # get_adapter should silently drop it rather than raise TypeError.
    adapter = get_adapter("http", target, model="ignored")
    assert adapter.adapter_type == "http"
