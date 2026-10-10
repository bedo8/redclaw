"""HTTP Agent Adapter — generic adapter for any HTTP-accessible AI agent."""

from __future__ import annotations

import copy
from typing import Any

import httpx
from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse, register_adapter
from redclaw.config import TargetConfig

OPENAI_PATH = "/v1/chat/completions"
# Endpoints tried in order until one answers with something other than 404/405.
CANDIDATE_PATHS = ("/chat", "/message", OPENAI_PATH, "/")
_NOT_HERE = {404, 405}


@register_adapter("http")
class HttpAgentAdapter(AgentAdapter):
    """Adapter for agents reachable over HTTP.

    Endpoint discovery: the first message is POSTed to ``/chat``,
    ``/message``, ``/v1/chat/completions`` and ``/`` in turn; the first path
    that does not answer 404 or 405 is remembered for the rest of the scan.
    If the target URL already has a path (``http://host/api/agent``) only
    that path is used.

    Body shapes:

    * ``/v1/chat/completions`` gets an OpenAI-format body
      (``model`` + ``messages`` with the full conversation so far).
    * Every other path gets ``{"message": ..., "conversation_id": ...}``.

    Each attack runs in its own :meth:`fork`, so conversation state from one
    attack never leaks into another, and forks may run concurrently.
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None
        self._conversation_id: str | None = None
        self._history: list[dict[str, str]] = []
        self._endpoint: str | None = None
        self._shared: dict[str, str | None] = {"endpoint": None}

    @property
    def adapter_type(self) -> str:
        return "http"

    @property
    def supports_concurrency(self) -> bool:
        return True

    def fork(self) -> HttpAgentAdapter:
        clone = copy.copy(self)
        clone._conversation_id = None
        clone._history = []
        return clone

    async def connect(self) -> None:
        """Create the HTTP client with auth, timeout and TLS settings."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._config.auth_token:
            headers["Authorization"] = f"Bearer {self._config.auth_token.get_secret_value()}"
        elif self._config.auth_header:
            headers["Authorization"] = self._config.auth_header.get_secret_value()

        if not self._config.verify_ssl:
            logger.warning("TLS certificate verification is disabled for the target")

        self._client = httpx.AsyncClient(
            base_url=self._config.url,
            headers=headers,
            timeout=httpx.Timeout(self._config.timeout_seconds),
            verify=self._config.verify_ssl,
            follow_redirects=False,
        )
        logger.info(f"HTTP adapter ready for {self._config.url}")

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    def _candidate_paths(self) -> tuple[str, ...]:
        known = self._shared.get("endpoint")
        if known is not None:
            return (known,)
        path = httpx.URL(self._config.url).path
        if path not in ("", "/"):
            # The URL itself is the endpoint. Post to it verbatim: a relative ""
            # would be resolved against base_url and gain a trailing slash.
            return (self._config.url,)
        return CANDIDATE_PATHS

    def _body(self, endpoint: str, message: str) -> dict[str, Any]:
        if endpoint.endswith(OPENAI_PATH):
            return {
                "model": self._config.model or "default",
                "messages": [*self._history, {"role": "user", "content": message}],
            }
        body: dict[str, Any] = {"message": message}
        if self._conversation_id:
            body["conversation_id"] = self._conversation_id
        return body

    async def send_message(self, message: str) -> AgentResponse:
        if not self._client:
            raise RuntimeError("Adapter not connected. Call connect() first.")

        last_status = 404
        for endpoint in self._candidate_paths():
            try:
                resp = await self._client.post(endpoint, json=self._body(endpoint, message))
            except httpx.ConnectError as exc:
                return AgentResponse(error=f"Connection failed: {exc}", status_code=0)
            except httpx.TimeoutException:
                return AgentResponse(error=f"Timeout on {endpoint or '/'}", status_code=0)
            except httpx.HTTPError as exc:
                return AgentResponse(error=f"HTTP error: {exc}", status_code=0)

            if resp.status_code in _NOT_HERE and len(self._candidate_paths()) > 1:
                last_status = resp.status_code
                continue

            if self._shared.get("endpoint") is None:
                self._shared["endpoint"] = endpoint
                logger.info(f"Using endpoint {endpoint or self._config.url}")

            parsed = self._parse_response(resp)
            if parsed.ok:
                self._history.append({"role": "user", "content": message})
                self._history.append({"role": "assistant", "content": parsed.text})
            return parsed

        return AgentResponse(error="No chat endpoint found on target", status_code=last_status)

    async def get_available_tools(self) -> list[dict[str, Any]]:
        """Try to discover agent tools via common endpoints."""
        if not self._client:
            return []
        for endpoint in ("/tools", "/v1/tools", "/capabilities"):
            try:
                resp = await self._client.get(endpoint)
                if resp.status_code != 200:
                    continue
                data = resp.json()
            except (httpx.HTTPError, ValueError):
                continue
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and isinstance(data.get("tools"), list):
                return data["tools"]
        return []

    # ------------------------------------------------------------------
    @staticmethod
    def _openai_text(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            return "", []
        message = choices[0].get("message") or {}
        if not isinstance(message, dict):
            return "", []
        content = message.get("content") or ""
        if isinstance(content, list):  # content-part arrays
            content = "".join(
                p.get("text", "")
                for p in content
                if isinstance(p, dict) and p.get("type") == "text"
            )
        tool_calls: list[dict[str, Any]] = []
        for tc in message.get("tool_calls") or []:
            if isinstance(tc, dict):
                fn = tc.get("function") or {}
                tool_calls.append(
                    {
                        "id": tc.get("id"),
                        "name": fn.get("name", ""),
                        "arguments": fn.get("arguments"),
                    }
                )
        return str(content), tool_calls

    def _parse_response(self, resp: httpx.Response) -> AgentResponse:
        """Parse an HTTP response into an AgentResponse."""
        error = None if resp.is_success else f"HTTP {resp.status_code}"
        try:
            data = resp.json()
        except ValueError:
            return AgentResponse(
                text=resp.text, status_code=resp.status_code, raw={"body": resp.text}, error=error
            )

        text = ""
        tool_calls: list[dict[str, Any]] = []
        if isinstance(data, str):
            text = data
        elif isinstance(data, dict):
            for key in ("response", "message", "content", "text", "output", "answer"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    text = value
                    break
            if not text and "choices" in data:
                text, tool_calls = self._openai_text(data)
            if isinstance(data.get("conversation_id"), str):
                self._conversation_id = data["conversation_id"]
            for key in ("tool_calls", "function_calls"):
                if not tool_calls and isinstance(data.get(key), list):
                    tool_calls = [tc for tc in data[key] if isinstance(tc, dict)]

        return AgentResponse(
            text=text,
            tool_calls=tool_calls,
            raw=data if isinstance(data, dict) else {"body": data},
            status_code=resp.status_code,
            error=error,
        )
