"""MCPAdapter over the official SDK: stdio (bundled mock server) and streamable HTTP."""

from __future__ import annotations

import shlex
import sys
import threading
import time

import pytest

from redclaw.adapters.mcp import MCPAdapter
from redclaw.config import AdapterType, TargetConfig

MOCK = f"{shlex.quote(sys.executable)} -m redclaw.mock_services.mock_mcp_server"


def _cfg(url: str, **kw) -> TargetConfig:
    kw.setdefault("timeout_seconds", 10)
    return TargetConfig(url=url, adapter=AdapterType.MCP, **kw)


async def test_stdio_poisoned_server() -> None:
    adapter = MCPAdapter(_cfg(f"{MOCK} --mode poisoned"))
    assert adapter.transport == "stdio"
    async with adapter:
        tools = await adapter.get_available_tools()
        assert [t["name"] for t in tools] == ["data_analyzer", "report_generator"]
        assert adapter.server_info["name"] == "mock-mcp-poisoned"
        resp = await adapter.send_message("hello")
    assert resp.ok
    assert "SYSTEM DIRECTIVE" in resp.text
    # Arguments were derived from the tool's schema and never surface as tool calls.
    assert resp.raw["arguments"] == {"data": "hello"}
    assert resp.tool_calls == []


async def test_stdio_named_tool_and_echo() -> None:
    async with MCPAdapter(_cfg(f"{MOCK} --mode echo", mcp_tool="echo")) as adapter:
        resp = await adapter.send_message("REDCLAW_X_CANARY_1")
    assert resp.text == "REDCLAW_X_CANARY_1"


async def test_stdio_missing_named_tool() -> None:
    async with MCPAdapter(_cfg(f"{MOCK} --mode clean", mcp_tool="nope")) as adapter:
        resp = await adapter.send_message("x")
    assert not resp.ok
    assert "nope" in (resp.error or "")


async def test_stdio_bad_command_reports_cleanly() -> None:
    adapter = MCPAdapter(_cfg("definitely-not-a-binary-redclaw --x"))
    with pytest.raises(RuntimeError, match="MCP connection"):
        await adapter.connect()
    await adapter.disconnect()  # idempotent


async def test_stdio_crashing_server_includes_stderr() -> None:
    cmd = f"{shlex.quote(sys.executable)} -c " + shlex.quote(
        "import sys; sys.stderr.write('boom-on-start\\n'); sys.exit(3)"
    )
    adapter = MCPAdapter(_cfg(cmd, timeout_seconds=5))
    with pytest.raises(RuntimeError) as info:
        await adapter.connect()
    assert "boom-on-start" in str(info.value)


def test_shlex_quoting_and_argument_building() -> None:
    tool = {"inputSchema": {"properties": {"a": {"type": "string"}, "n": {"type": "integer"}}}}
    assert MCPAdapter.build_arguments(tool, "m") == {"a": "m"}
    assert MCPAdapter.build_arguments({}, "m") == {"input": "m"}
    assert shlex.split('python "my server.py" --flag') == ["python", "my server.py", "--flag"]


async def test_send_before_connect() -> None:
    with pytest.raises(RuntimeError, match="not connected"):
        await MCPAdapter(_cfg(MOCK)).send_message("x")


@pytest.fixture
def streamable_http_server():
    uvicorn = pytest.importorskip("uvicorn")
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("redclaw-test")

    @server.tool()
    def lookup(query: str) -> str:
        """Look something up."""
        return f"result for {query}"

    from tests.conftest import free_port

    port = free_port()
    config = uvicorn.Config(
        server.streamable_http_app(), host="127.0.0.1", port=port, log_level="error"
    )
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started and time.time() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    uv.should_exit = True
    thread.join(5)


async def test_streamable_http(streamable_http_server: str) -> None:
    adapter = MCPAdapter(_cfg(streamable_http_server))
    assert adapter.transport == "streamable-http"
    async with adapter:
        assert [t["name"] for t in await adapter.get_available_tools()] == ["lookup"]
        resp = await adapter.send_message("canary-123")
    assert resp.ok
    assert resp.text == "result for canary-123"
