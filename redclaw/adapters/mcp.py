"""MCP adapter — talks to MCP servers through the official ``mcp`` Python SDK.

Transports:

* **stdio**: ``--target`` is a command line, e.g.
  ``"python -m redclaw.mock_services.mock_mcp_server --mode poisoned"``.
  It is split with :func:`shlex.split` (quotes work) and launched without a
  shell. The server's stderr is captured to a temporary file and its tail is
  attached to connection errors.
* **Streamable HTTP**: ``--target`` is an ``http(s)://`` URL of the MCP
  endpoint, e.g. ``http://127.0.0.1:8000/mcp``. The legacy HTTP+SSE
  transport (protocol 2024-11-05) is not supported.

MCP servers have no chat; each payload is passed as the argument of one
tool (``--mcp-tool``, default: the first listed tool). The adapter fills
every string parameter in the tool's input schema with the payload, so the
server sees it whichever field it reads.
"""

from __future__ import annotations

import contextlib
import shlex
import tempfile
from typing import Any, TextIO

from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse, register_adapter
from redclaw.config import TargetConfig
from redclaw.version import __version__

try:  # the SDK is a core dependency, but keep the import error readable
    import mcp.types as mcp_types
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
except ImportError:  # pragma: no cover
    ClientSession = None  # type: ignore[assignment,misc]


@register_adapter("mcp")
class MCPAdapter(AgentAdapter):
    """Adapter for testing MCP servers (AATCK-005 and friends)."""

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._stack: contextlib.AsyncExitStack | None = None
        self._session: Any = None
        self._stderr: TextIO | None = None
        self._tools: list[dict[str, Any]] = []
        self.server_info: dict[str, Any] = {}

    @property
    def adapter_type(self) -> str:
        return "mcp"

    @property
    def transport(self) -> str:
        return (
            "streamable-http" if self._config.url.startswith(("http://", "https://")) else "stdio"
        )

    # ------------------------------------------------------------------
    async def connect(self) -> None:
        if ClientSession is None:  # pragma: no cover
            raise RuntimeError("The 'mcp' package is required: pip install mcp")

        stack = contextlib.AsyncExitStack()
        await stack.__aenter__()
        self._stack = stack
        try:
            if self.transport == "stdio":
                streams = await self._open_stdio(stack)
            else:
                streams = await self._open_http(stack)
            read, write = streams[0], streams[1]
            session = await stack.enter_async_context(
                ClientSession(
                    read,
                    write,
                    read_timeout_seconds=float(self._config.timeout_seconds),
                    client_info=mcp_types.Implementation(name="redclaw", version=__version__),
                )
            )
            init = await session.initialize()
            self._session = session
            info = getattr(init, "server_info", None)
            self.server_info = info.model_dump() if info is not None else {}
            self._tools = await self._list_tools()
            logger.info(
                f"MCP {self.transport} session open: {self.server_info.get('name', '?')} "
                f"with {len(self._tools)} tools"
            )
        except BaseException as exc:
            detail = self._stderr_tail()
            await self.disconnect()
            if isinstance(exc, Exception):
                msg = f"MCP connection to {self._config.url!r} failed: {exc}"
                if detail:
                    msg += f"\nServer stderr (tail):\n{detail}"
                raise RuntimeError(msg) from exc
            raise

    async def _open_stdio(self, stack: contextlib.AsyncExitStack) -> Any:
        argv = shlex.split(self._config.url)
        if not argv:
            raise ValueError("empty MCP command line")
        # Drain the child's stderr into a temp file so a chatty server can never
        # block on a full pipe, and so we can show its tail on failure.
        errlog = tempfile.TemporaryFile(  # noqa: SIM115 - closed by the exit stack
            mode="w+", encoding="utf-8", errors="replace"
        )
        self._stderr = stack.enter_context(errlog)
        params = StdioServerParameters(command=argv[0], args=argv[1:])
        logger.info(f"Launching MCP server: {argv}")
        return await stack.enter_async_context(stdio_client(params, errlog=self._stderr))

    async def _open_http(self, stack: contextlib.AsyncExitStack) -> Any:
        headers: dict[str, str] = {}
        if self._config.auth_token:
            headers["Authorization"] = f"Bearer {self._config.auth_token.get_secret_value()}"
        elif self._config.auth_header:
            headers["Authorization"] = self._config.auth_header.get_secret_value()
        http_client = create_mcp_http_client(headers=headers or None)
        if not self._config.verify_ssl:
            await http_client.aclose()
            import httpx2

            http_client = httpx2.AsyncClient(
                headers=headers or None, verify=False, timeout=self._config.timeout_seconds
            )
        await stack.enter_async_context(http_client)
        return await stack.enter_async_context(
            streamable_http_client(self._config.url, http_client=http_client)
        )

    async def disconnect(self) -> None:
        stack, self._stack = self._stack, None
        self._session = None
        if stack is not None:
            with contextlib.suppress(Exception):
                await stack.aclose()
        self._stderr = None

    def _stderr_tail(self, limit: int = 2000) -> str:
        if self._stderr is None:
            return ""
        with contextlib.suppress(Exception):
            self._stderr.flush()
            self._stderr.seek(0)
            return self._stderr.read()[-limit:].strip()
        return ""

    # ------------------------------------------------------------------
    async def _list_tools(self) -> list[dict[str, Any]]:
        result = await self._session.list_tools()
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.input_schema or {},
            }
            for t in result.tools
        ]

    async def get_available_tools(self) -> list[dict[str, Any]]:
        return list(self._tools)

    def _pick_tool(self) -> dict[str, Any] | None:
        if not self._tools:
            return None
        if self._config.mcp_tool:
            for tool in self._tools:
                if tool["name"] == self._config.mcp_tool:
                    return tool
            return None
        return self._tools[0]

    @staticmethod
    def build_arguments(tool: dict[str, Any], message: str) -> dict[str, Any]:
        """Put ``message`` into every string parameter the tool declares."""
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        args = {
            name: message
            for name, spec in props.items()
            if isinstance(spec, dict) and spec.get("type", "string") == "string"
        }
        return args or {"input": message}

    async def send_message(self, message: str) -> AgentResponse:
        if self._session is None:
            raise RuntimeError("Adapter not connected. Call connect() first.")
        tool = self._pick_tool()
        if tool is None:
            wanted = self._config.mcp_tool or "any tool"
            return AgentResponse(error=f"MCP server does not expose {wanted}", status_code=0)

        arguments = self.build_arguments(tool, message)
        try:
            result = await self._session.call_tool(tool["name"], arguments)
        except Exception as exc:
            return AgentResponse(error=f"MCP tools/call failed: {exc}", status_code=0)

        parts: list[str] = []
        for block in getattr(result, "content", None) or []:
            if getattr(block, "type", "") == "text":
                parts.append(block.text)
            elif getattr(block, "type", "") == "resource":
                resource = getattr(block, "resource", None)
                if resource is not None and hasattr(resource, "text"):
                    parts.append(resource.text)
        raw = result.model_dump(mode="json") if hasattr(result, "model_dump") else {}
        text = "\n".join(parts)
        if not text and raw.get("structured_content"):
            text = str(raw["structured_content"])

        # Only server output is observed. The call itself is kept in ``raw``:
        # its arguments contain the payload (and its canary), so exposing them
        # as tool_calls would make every attack look successful. A tool-level
        # error (isError) is still a response the server chose to send.
        return AgentResponse(
            text=text,
            raw={"tool": tool["name"], "arguments": arguments, "result": raw},
            status_code=200,
        )
