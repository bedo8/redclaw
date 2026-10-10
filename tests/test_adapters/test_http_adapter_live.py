"""HttpAgentAdapter against real loopback HTTP servers."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from redclaw.adapters.http_agent import HttpAgentAdapter
from redclaw.config import AdapterType, TargetConfig


def _cfg(url: str, **kw: Any) -> TargetConfig:
    return TargetConfig(url=url, adapter=AdapterType.HTTP, timeout_seconds=5, **kw)


async def test_openai_endpoint_gets_openai_body_and_405_is_skipped(json_server) -> None:
    def handler(method, path, headers, body):
        if path in ("/chat", "/message"):
            return 405, {"error": "method not allowed"}
        if path == "/v1/chat/completions":
            return 200, {"choices": [{"message": {"role": "assistant", "content": "hi there"}}]}
        return 404, {}

    srv = json_server(handler)
    adapter = HttpAgentAdapter(_cfg(srv.url, model="gpt-test"))
    async with adapter:
        session = adapter.fork()
        first = await session.send_message("one")
        second = await session.send_message("two")
    assert first.ok and first.text == "hi there"
    assert second.text == "hi there"
    posts = [r for r in srv.requests if r["path"] == "/v1/chat/completions"]
    assert posts[0]["body"] == {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "one"}],
    }
    # The conversation is replayed in OpenAI format on the next turn.
    assert [m["content"] for m in posts[1]["body"]["messages"]] == ["one", "hi there", "two"]
    # Endpoint is discovered once, then reused.
    assert sum(1 for r in srv.requests if r["path"] == "/chat") == 1


async def test_empty_choices_does_not_crash(json_server) -> None:
    srv = json_server(lambda *a: (200, {"choices": []}))
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        resp = await adapter.send_message("x")
    assert resp.ok
    assert resp.text == ""


@pytest.mark.parametrize(
    "payload",
    [
        {"choices": [None]},
        {"choices": [{"message": None}]},
        {"choices": "nope"},
        {"choices": [{"message": {"content": [{"type": "text", "text": "parts"}]}}]},
    ],
)
async def test_odd_openai_shapes(json_server, payload) -> None:
    srv = json_server(lambda *a: (200, payload))
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        resp = await adapter.send_message("x")
    assert resp.ok
    assert resp.text in ("", "parts")


async def test_openai_tool_calls_are_extracted(json_server) -> None:
    srv = json_server(
        lambda *a: (
            200,
            {
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {"id": "c1", "function": {"name": "bash", "arguments": "{}"}}
                            ],
                        }
                    }
                ]
            },
        )
    )
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        resp = await adapter.send_message("x")
    assert resp.tool_calls == [{"id": "c1", "name": "bash", "arguments": "{}"}]


async def test_bearer_token_and_custom_path(json_server) -> None:
    srv = json_server(lambda *a: (200, {"response": "ok", "conversation_id": "c-1"}))
    cfg = _cfg(f"{srv.url}/api/agent", auth_token=SecretStr("tok-123"))
    async with HttpAgentAdapter(cfg) as adapter:
        session = adapter.fork()
        await session.send_message("a")
        await session.send_message("b")
    assert [r["path"] for r in srv.requests] == ["/api/agent", "/api/agent"]
    assert srv.requests[0]["headers"]["authorization"] == "Bearer tok-123"
    assert srv.requests[1]["body"]["conversation_id"] == "c-1"


async def test_raw_auth_header(json_server) -> None:
    srv = json_server(lambda *a: (200, {"text": "ok"}))
    cfg = _cfg(srv.url, auth_header=SecretStr("Basic dXNlcjpwYXNz"))
    async with HttpAgentAdapter(cfg) as adapter:
        await adapter.send_message("a")
    assert srv.requests[0]["headers"]["authorization"] == "Basic dXNlcjpwYXNz"


async def test_forks_do_not_share_conversation(json_server) -> None:
    srv = json_server(lambda *a: (200, {"response": "ok", "conversation_id": "c-1"}))
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        await adapter.fork().send_message("a")
        await adapter.fork().send_message("b")
    assert "conversation_id" not in srv.requests[-1]["body"]


async def test_http_errors_are_errors(json_server) -> None:
    srv = json_server(lambda *a: (500, {"response": "boom"}))
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        resp = await adapter.send_message("x")
    assert not resp.ok
    assert resp.error == "HTTP 500"


async def test_no_endpoint_found(json_server) -> None:
    srv = json_server(lambda *a: (404, {}))
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        resp = await adapter.send_message("x")
    assert not resp.ok
    assert "No chat endpoint" in (resp.error or "")


async def test_plain_text_response(json_server) -> None:
    srv = json_server(lambda *a: (200, "just text"))
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        resp = await adapter.send_message("x")
    assert resp.text == "just text"


async def test_unreachable_target() -> None:
    from tests.conftest import free_port

    async with HttpAgentAdapter(_cfg(f"http://127.0.0.1:{free_port()}")) as adapter:
        resp = await adapter.send_message("x")
    assert not resp.ok
    assert "Connection failed" in (resp.error or "")


async def test_tool_discovery(json_server) -> None:
    def handler(method, path, headers, body):
        if path == "/capabilities":
            return 200, {"tools": [{"name": "t"}]}
        return 404, {}

    srv = json_server(handler)
    async with HttpAgentAdapter(_cfg(srv.url)) as adapter:
        assert await adapter.get_available_tools() == [{"name": "t"}]
    assert await HttpAgentAdapter(_cfg(srv.url)).get_available_tools() == []


async def test_insecure_flag_disables_verification() -> None:
    adapter = HttpAgentAdapter(_cfg("https://agent.example.com", verify_ssl=False))
    await adapter.connect()
    try:
        assert adapter._client is not None
    finally:
        await adapter.disconnect()
    assert adapter.supports_concurrency is True
