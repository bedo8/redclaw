"""Tests for HttpAgentAdapter response parsing using httpx.MockTransport.

We don't spin up a real HTTP server — instead we swap the adapter's client
for one backed by a MockTransport after connect(). That lets us assert:
- standard /chat JSON responses are parsed correctly
- endpoint discovery falls back past 404s
- OpenAI-compatible choices[].message.content extraction works
- get_available_tools() handles both list and dict shapes
"""

from __future__ import annotations

import json

import httpx
import pytest

from redclaw.adapters.http_agent import HttpAgentAdapter
from redclaw.config import AdapterType, TargetConfig


def _make_adapter(handler) -> HttpAgentAdapter:
    """Build a connected adapter whose client talks to a MockTransport."""
    cfg = TargetConfig(url="http://mock.local", adapter=AdapterType.HTTP)
    adapter = HttpAgentAdapter(cfg)
    transport = httpx.MockTransport(handler)
    adapter._client = httpx.AsyncClient(
        base_url=cfg.url,
        transport=transport,
        timeout=5.0,
    )
    return adapter


@pytest.mark.asyncio
async def test_send_message_parses_chat_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/chat"
        body = json.loads(request.content)
        assert body["message"] == "hi"
        return httpx.Response(
            200,
            json={"response": "pong", "conversation_id": "abc-123"},
        )

    adapter = _make_adapter(handler)
    try:
        resp = await adapter.send_message("hi")
        assert resp.ok
        assert resp.text == "pong"
        # conversation_id is tracked so subsequent calls reuse it.
        assert adapter._conversation_id == "abc-123"
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_send_message_falls_back_past_404() -> None:
    """Adapter should walk the endpoint list when one returns 404."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path in ("/chat", "/message"):
            return httpx.Response(404, text="not found")
        return httpx.Response(200, json={"text": "from openai-compat"})

    adapter = _make_adapter(handler)
    try:
        resp = await adapter.send_message("ping")
        assert resp.ok
        assert resp.text == "from openai-compat"
        assert "/chat" in calls and "/v1/chat/completions" in calls
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_send_message_openai_choices_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "hello from llm"}}]},
        )

    adapter = _make_adapter(handler)
    try:
        resp = await adapter.send_message("x")
        assert resp.text == "hello from llm"
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_get_available_tools_list_shape() -> None:
    tools = [{"name": "shell"}, {"name": "file_read"}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tools":
            return httpx.Response(200, json=tools)
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    try:
        result = await adapter.get_available_tools()
        assert result == tools
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_get_available_tools_dict_shape() -> None:
    tools = [{"name": "shell"}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tools":
            return httpx.Response(200, json={"tools": tools, "version": 1})
        return httpx.Response(404)

    adapter = _make_adapter(handler)
    try:
        result = await adapter.get_available_tools()
        assert result == tools
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_connect_disconnect_round_trip() -> None:
    """Lifecycle: real connect() sets a client; disconnect() clears it."""
    cfg = TargetConfig(
        url="http://mock.local",
        adapter=AdapterType.HTTP,
        auth_token="secret-token",
    )
    adapter = HttpAgentAdapter(cfg)
    await adapter.connect()
    assert adapter._client is not None
    # Authorization header should be set from the bearer token.
    assert adapter._client.headers.get("authorization") == "Bearer secret-token"
    await adapter.disconnect()
    assert adapter._client is None
