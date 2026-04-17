"""MCP Adapter — communicates with MCP servers via stdio or SSE."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse
from redclaw.config import TargetConfig


class MCPAdapter(AgentAdapter):
    """Adapter for testing MCP (Model Context Protocol) servers.

    Supports two transport modes:
    - stdio: launches the MCP server as a subprocess and communicates via stdin/stdout
    - sse: connects to an MCP server via Server-Sent Events over HTTP

    For RedClaw, the primary use case is testing MCP servers for AATCK-005
    (MCP Exploitation) by sending crafted messages and observing responses.
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._process: asyncio.subprocess.Process | None = None
        self._request_id: int = 0
        self._is_stdio = not config.url.startswith("http")

    @property
    def adapter_type(self) -> str:
        return "mcp"

    async def connect(self) -> None:
        if self._is_stdio:
            await self._connect_stdio()
        else:
            logger.info(f"MCP SSE mode: {self._config.url} (send via HTTP)")

    async def _connect_stdio(self) -> None:
        """Launch MCP server as subprocess."""
        cmd = self._config.url  # For stdio, url is the command to run
        logger.info(f"Launching MCP server: {cmd}")

        self._process = await asyncio.create_subprocess_exec(
            *cmd.split(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Send initialize request
        init_result = await self._send_jsonrpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "redclaw", "version": "0.1.0"},
        })
        logger.info(f"MCP server initialized: {init_result}")

        # Send initialized notification
        await self._send_notification("notifications/initialized", {})

    async def disconnect(self) -> None:
        if self._process:
            self._process.terminate()
            await self._process.wait()
            self._process = None
            logger.info("MCP server process terminated")

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message by calling the MCP server's tools.

        Since MCP servers don't have a "chat" concept, we:
        1. List available tools
        2. Call the first tool with the message as input
        3. Return the result
        """
        if self._is_stdio:
            return await self._send_message_stdio(message)
        return await self._send_message_sse(message)

    async def _send_message_stdio(self, message: str) -> AgentResponse:
        """Send via stdio JSON-RPC."""
        # Try calling a tool with the message
        tools = await self.get_available_tools()
        if not tools:
            return AgentResponse(error="No tools available on MCP server")

        # Use first tool, pass message as argument
        tool = tools[0]
        tool_name = tool.get("name", "unknown")

        result = await self._send_jsonrpc("tools/call", {
            "name": tool_name,
            "arguments": {"input": message, "query": message},
        })

        if result is None:
            return AgentResponse(error="No response from MCP server")

        # Extract text from result
        text = ""
        tool_calls: list[dict] = []
        if isinstance(result, dict):
            content = result.get("content", [])
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text += item.get("text", "")
            tool_calls = [{"name": tool_name, "arguments": message, "result": result}]

        return AgentResponse(text=text, tool_calls=tool_calls, raw=result)

    async def _send_message_sse(self, message: str) -> AgentResponse:
        """Send via HTTP to SSE-based MCP server."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                resp = await client.post(
                    f"{self._config.url}/message",
                    json={"jsonrpc": "2.0", "method": "tools/call", "id": self._next_id(),
                          "params": {"name": "query", "arguments": {"input": message}}},
                )
                data = resp.json()
                result = data.get("result", {})
                text = ""
                content = result.get("content", [])
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text += item.get("text", "")
                return AgentResponse(text=text, raw=data, status_code=resp.status_code)
        except Exception as exc:
            return AgentResponse(error=str(exc))

    async def get_available_tools(self) -> list[dict[str, Any]]:
        """List tools available on the MCP server."""
        if self._is_stdio:
            result = await self._send_jsonrpc("tools/list", {})
            if isinstance(result, dict):
                return result.get("tools", [])
            return []

        # SSE mode
        import httpx
        try:
            async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                resp = await client.post(
                    f"{self._config.url}/message",
                    json={"jsonrpc": "2.0", "method": "tools/list", "id": self._next_id(), "params": {}},
                )
                data = resp.json()
                return data.get("result", {}).get("tools", [])
        except Exception:
            return []

    async def _send_jsonrpc(self, method: str, params: dict) -> dict | None:
        """Send JSON-RPC request via stdio."""
        if not self._process or not self._process.stdin or not self._process.stdout:
            return None

        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params,
        }

        line = json.dumps(request) + "\n"
        self._process.stdin.write(line.encode())
        await self._process.stdin.drain()

        try:
            response_line = await asyncio.wait_for(
                self._process.stdout.readline(),
                timeout=self._config.timeout_seconds,
            )
            if response_line:
                data = json.loads(response_line.decode())
                return data.get("result")
        except (TimeoutError, json.JSONDecodeError) as exc:
            logger.warning(f"MCP response error: {exc}")

        return None

    async def _send_notification(self, method: str, params: dict) -> None:
        """Send JSON-RPC notification (no response expected)."""
        if not self._process or not self._process.stdin:
            return

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }

        line = json.dumps(notification) + "\n"
        self._process.stdin.write(line.encode())
        await self._process.stdin.drain()

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id
