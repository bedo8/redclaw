"""HTTP Agent Adapter — generic adapter for any HTTP-accessible AI agent."""

from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse, register_adapter
from redclaw.config import TargetConfig


@register_adapter("http")
class HttpAgentAdapter(AgentAdapter):
    """Adapter for agents accessible via HTTP API.

    Supports common patterns:
    - POST /chat or /message with {"message": "..."} body
    - Bearer token or custom header authentication
    - JSON response parsing with tool call extraction
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None
        self._conversation_id: str | None = None

    @property
    def adapter_type(self) -> str:
        return "http"

    async def connect(self) -> None:
        """Create HTTP client with configured auth and timeouts."""
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self._config.auth_token:
            headers["Authorization"] = f"Bearer {self._config.auth_token.get_secret_value()}"
        elif self._config.auth_header:
            headers["Authorization"] = self._config.auth_header.get_secret_value()

        self._client = httpx.AsyncClient(
            base_url=self._config.url,
            headers=headers,
            timeout=httpx.Timeout(self._config.timeout_seconds),
            verify=self._config.verify_ssl,
        )
        logger.info(f"Connected to HTTP agent at {self._config.url}")

    async def disconnect(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Disconnected from HTTP agent")

    async def send_message(self, message: str) -> AgentResponse:
        """Send message to agent via POST request.

        Tries common endpoint patterns in order:
        1. /chat
        2. /message
        3. /v1/chat/completions (OpenAI-compatible)
        4. / (root)
        """
        if not self._client:
            raise RuntimeError("Adapter not connected. Call connect() first.")

        # Build request body — try common patterns
        body: dict[str, Any] = {"message": message}
        if self._conversation_id:
            body["conversation_id"] = self._conversation_id

        endpoints = ["/chat", "/message", "/v1/chat/completions", "/"]

        for endpoint in endpoints:
            try:
                resp = await self._client.post(endpoint, json=body)

                if resp.status_code == 404:
                    continue

                return self._parse_response(resp)

            except httpx.ConnectError:
                logger.error(f"Connection failed to {self._config.url}{endpoint}")
                return AgentResponse(error=f"Connection failed to {self._config.url}")
            except httpx.TimeoutException:
                logger.warning(f"Timeout on {endpoint}")
                return AgentResponse(error=f"Timeout on {endpoint}")

        return AgentResponse(error="No valid endpoint found", status_code=404)

    async def get_available_tools(self) -> list[dict[str, Any]]:
        """Try to discover agent tools via common endpoints."""
        if not self._client:
            return []

        for endpoint in ["/tools", "/v1/tools", "/capabilities"]:
            try:
                resp = await self._client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        return data
                    return data.get("tools", [])
            except (httpx.HTTPError, ValueError):
                continue

        return []

    def _parse_response(self, resp: httpx.Response) -> AgentResponse:
        """Parse HTTP response into standardized AgentResponse."""
        try:
            data = resp.json()
        except ValueError:
            return AgentResponse(
                text=resp.text,
                status_code=resp.status_code,
                raw={"body": resp.text},
            )

        # Extract text — try common response shapes
        text = ""
        if isinstance(data, str):
            text = data
        elif isinstance(data, dict):
            text = (
                data.get("response", "")
                or data.get("message", "")
                or data.get("content", "")
                or data.get("text", "")
                or str(data.get("choices", [{}])[0].get("message", {}).get("content", ""))
            )

            # Track conversation ID if returned
            if "conversation_id" in data:
                self._conversation_id = data["conversation_id"]

        # Extract tool calls if present
        tool_calls: list[dict[str, Any]] = []
        if isinstance(data, dict):
            tool_calls = data.get("tool_calls", []) or data.get("function_calls", []) or []

        return AgentResponse(
            text=str(text),
            tool_calls=tool_calls,
            raw=data if isinstance(data, dict) else {"body": data},
            status_code=resp.status_code,
        )
