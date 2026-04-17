"""Tests for the HTTP agent adapter."""

import pytest

from redclaw.adapters.http_agent import HttpAgentAdapter
from redclaw.config import AdapterType, TargetConfig


def test_adapter_type():
    config = TargetConfig(url="http://localhost:9999", adapter=AdapterType.HTTP)
    adapter = HttpAgentAdapter(config)
    assert adapter.adapter_type == "http"


def test_adapter_not_connected():
    config = TargetConfig(url="http://localhost:9999", adapter=AdapterType.HTTP)
    adapter = HttpAgentAdapter(config)
    with pytest.raises(RuntimeError, match="not connected"):
        import asyncio

        asyncio.run(adapter.send_message("test"))
