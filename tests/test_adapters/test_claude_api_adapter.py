"""ClaudeAPIAdapter against a local fake of the Messages API (no network)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from redclaw.adapters.claude_api import ClaudeAPIAdapter
from redclaw.config import (
    CLAUDE_MODEL_DEFAULT,
    CLAUDE_MODEL_FAST,
    CLAUDE_MODEL_HEAVY,
    AdapterType,
    RedClawSettings,
    TargetConfig,
)


def _message(content: list[dict[str, Any]], model: str = "m") -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 3, "output_tokens": 4},
    }


@pytest.fixture
def fake_api(json_server):
    replies: list[dict[str, Any]] = []

    def handler(method, path, headers, body):
        if path != "/v1/messages":
            return 404, {}
        if replies:
            return 200, replies.pop(0)
        return 200, _message([{"type": "text", "text": "default reply"}], body["model"])

    srv = json_server(handler)
    srv.replies = replies
    return srv


def _cfg(url: str = "", **kw: Any) -> TargetConfig:
    return TargetConfig(url=url, adapter=AdapterType.CLAUDE_API, timeout_seconds=5, **kw)


async def test_uses_standard_env_vars(fake_api, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", fake_api.url)
    adapter = ClaudeAPIAdapter(_cfg(system_prompt="You are a test agent."))
    assert adapter.model == CLAUDE_MODEL_DEFAULT
    async with adapter:
        resp = await adapter.send_message("hello")
    assert resp.ok and resp.text == "default reply"
    req = fake_api.requests[0]
    assert req["headers"]["x-api-key"] == "env-key"
    assert req["body"]["model"] == CLAUDE_MODEL_DEFAULT
    assert req["body"]["system"] == "You are a test agent."


async def test_token_and_target_url_override_env(fake_api, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://198.51.100.1:1")
    cfg = _cfg(fake_api.url, auth_token=SecretStr("cli-key"), model="heavy")
    async with ClaudeAPIAdapter(cfg) as adapter:
        await adapter.send_message("x")
    assert fake_api.requests[0]["headers"]["x-api-key"] == "cli-key"
    assert fake_api.requests[0]["body"]["model"] == CLAUDE_MODEL_HEAVY


def test_model_aliases_and_env_default(monkeypatch) -> None:
    assert ClaudeAPIAdapter(_cfg(model="fast")).model == CLAUDE_MODEL_FAST
    assert ClaudeAPIAdapter(_cfg(model="claude-custom-1")).model == "claude-custom-1"
    monkeypatch.setenv("REDCLAW_CLAUDE_MODEL", "heavy")
    assert ClaudeAPIAdapter(_cfg()).model == CLAUDE_MODEL_HEAVY


async def test_missing_key_is_a_clear_error() -> None:
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        await ClaudeAPIAdapter(_cfg()).connect()


async def test_multi_turn_and_tool_use_keep_conversation_valid(fake_api) -> None:
    fake_api.replies.extend(
        [
            _message(
                [
                    {"type": "text", "text": "running"},
                    {"type": "tool_use", "id": "tu_1", "name": "bash", "input": {"cmd": "ls"}},
                ]
            ),
            _message([{"type": "text", "text": "done"}]),
        ]
    )
    tools = [{"name": "bash", "description": "run", "input_schema": {"type": "object"}}]
    cfg = _cfg(fake_api.url, auth_token=SecretStr("k"))
    async with ClaudeAPIAdapter(cfg, tools=tools) as adapter:
        session = adapter.fork()
        responses = await session.send_multi_turn(["one", "two"])
        assert await session.get_available_tools() == tools
    assert [r.text for r in responses] == ["running", "done"]
    assert responses[0].tool_calls == [{"id": "tu_1", "name": "bash", "arguments": {"cmd": "ls"}}]
    second = fake_api.requests[1]["body"]["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "user", "user"]
    assert second[2]["content"][0]["type"] == "tool_result"
    assert second[2]["content"][0]["tool_use_id"] == "tu_1"


async def test_api_errors_become_error_responses(json_server) -> None:
    srv = json_server(
        lambda *a: (401, {"type": "error", "error": {"type": "auth", "message": "x"}})
    )
    settings = RedClawSettings()
    cfg = _cfg(srv.url, auth_token=SecretStr("bad"))
    async with ClaudeAPIAdapter(cfg, settings=settings) as adapter:
        resps = await adapter.send_multi_turn(["a", "b"])
    assert len(resps) == 1  # stops at first error
    assert not resps[0].ok
    assert resps[0].status_code == 401


async def test_injected_client_and_helpers() -> None:
    class Fake:
        class messages:  # noqa: N801
            @staticmethod
            async def create(**kw: Any) -> Any:
                raise RuntimeError("nope")

    adapter = ClaudeAPIAdapter(_cfg(), client=Fake())
    await adapter.connect()  # no-op with injected client
    resp = await adapter.send_message("x")
    assert resp.error and "nope" in resp.error
    adapter.set_system_prompt("p")
    adapter.set_tools([])
    adapter.reset_conversation()
    await adapter.disconnect()
    with pytest.raises(RuntimeError):
        await adapter.send_message("x")
