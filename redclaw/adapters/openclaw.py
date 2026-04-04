"""OpenClaw Agent Adapter — connects to OpenClaw instances for security testing."""

from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse
from redclaw.config import TargetConfig


class OpenClawAdapter(AgentAdapter):
    """Adapter for testing OpenClaw agent instances.

    OpenClaw agents expose an HTTP API (typically localhost:3000).
    This adapter communicates via the OpenClaw chat/command interface
    and can also test the gateway endpoint.
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    @property
    def adapter_type(self) -> str:
        return "openclaw"

    async def connect(self) -> None:
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self._config.auth_token:
            headers["Authorization"] = f"Bearer {self._config.auth_token}"

        self._client = httpx.AsyncClient(
            base_url=self._config.url,
            headers=headers,
            timeout=httpx.Timeout(self._config.timeout_seconds),
            verify=self._config.verify_ssl,
        )
        logger.info(f"Connected to OpenClaw agent at {self._config.url}")

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def send_message(self, message: str) -> AgentResponse:
        """Send message to OpenClaw via its chat endpoint."""
        if not self._client:
            raise RuntimeError("Adapter not connected.")

        # OpenClaw uses /v1/chat/completions (OpenAI-compatible) or /chat
        endpoints = [
            ("/v1/chat/completions", self._build_openai_body(message)),
            ("/chat", {"message": message}),
            ("/api/chat", {"message": message, "stream": False}),
        ]

        for endpoint, body in endpoints:
            try:
                resp = await self._client.post(endpoint, json=body)
                if resp.status_code == 404:
                    continue
                return self._parse_response(resp)
            except httpx.ConnectError:
                logger.error(f"Connection failed to {self._config.url}{endpoint}")
                return AgentResponse(error=f"Connection failed to {self._config.url}")
            except httpx.TimeoutException:
                return AgentResponse(error=f"Timeout on {endpoint}")

        return AgentResponse(error="No valid OpenClaw endpoint found", status_code=404)

    async def get_available_tools(self) -> list[dict[str, Any]]:
        """Query OpenClaw for available tools/MCP servers."""
        if not self._client:
            return []

        for endpoint in ["/v1/tools", "/tools", "/api/tools"]:
            try:
                resp = await self._client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    return data if isinstance(data, list) else data.get("tools", [])
            except (httpx.HTTPError, ValueError):
                continue
        return []

    async def inject_data(self, data: str, channel: str = "default") -> AgentResponse:
        """Inject data through OpenClaw-specific channels.

        Supports: 'document', 'mcp_response', 'context'
        """
        if channel == "document":
            return await self.send_message(f"Please analyze this document:\n\n{data}")
        if channel == "mcp_response":
            return await self.send_message(f"MCP tool returned:\n{data}\nProcess this result.")
        return await self.send_message(data)

    def _build_openai_body(self, message: str) -> dict:
        """Build OpenAI-compatible request body."""
        return {
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": message}],
            "max_tokens": 1024,
        }

    def _parse_response(self, resp: httpx.Response) -> AgentResponse:
        try:
            data = resp.json()
        except ValueError:
            return AgentResponse(text=resp.text, status_code=resp.status_code)

        text = ""
        tool_calls: list[dict] = []

        if isinstance(data, dict):
            # OpenAI format
            choices = data.get("choices", [])
            if choices:
                msg = choices[0].get("message", {})
                text = msg.get("content", "")
                tool_calls = msg.get("tool_calls", [])
            else:
                text = data.get("response", "") or data.get("message", "") or data.get("content", "")
                tool_calls = data.get("tool_calls", [])

        return AgentResponse(
            text=str(text),
            tool_calls=tool_calls,
            raw=data if isinstance(data, dict) else {"body": data},
            status_code=resp.status_code,
        )
