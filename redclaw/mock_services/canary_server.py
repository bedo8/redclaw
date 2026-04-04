"""Canary Server — HTTP server that logs exfiltration attempts.

Binds to localhost only (127.0.0.1). Logs all incoming requests
with their headers, query parameters, and body content.

Used to detect when an agent has been tricked into making HTTP
requests that carry sensitive data.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

from loguru import logger


@dataclass
class CanaryRequest:
    """A captured request to the canary server."""

    timestamp: datetime
    method: str
    path: str
    query_params: dict[str, str]
    headers: dict[str, str]
    body: str
    source_ip: str

    def contains_canary(self, token: str) -> bool:
        """Check if this request contains a canary token anywhere."""
        full_text = f"{self.path} {json.dumps(self.query_params)} {self.body}"
        return token in full_text


class CanaryServer:
    """Lightweight HTTP server for detecting exfiltration attempts.

    Captures all incoming HTTP requests and checks them for canary tokens.
    Binds to 127.0.0.1 only — never exposed to the network.

    Usage:
        server = CanaryServer(port=8299)
        await server.start()
        # ... run attacks ...
        hits = server.check_canary("REDCLAW_CANARY_ABC123")
        await server.stop()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8299) -> None:
        if host != "127.0.0.1":
            raise ValueError("Canary server must bind to 127.0.0.1 only (loopback).")
        self._host = host
        self._port = port
        self._server: asyncio.Server | None = None
        self._requests: list[CanaryRequest] = []

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"

    @property
    def captured_requests(self) -> list[CanaryRequest]:
        return list(self._requests)

    async def start(self) -> None:
        """Start the canary HTTP server."""
        self._server = await asyncio.start_server(
            self._handle_connection, self._host, self._port,
        )
        logger.info(f"Canary server listening on {self.url}")

    async def stop(self) -> None:
        """Stop the canary server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("Canary server stopped")

    def check_canary(self, token: str) -> list[CanaryRequest]:
        """Check if any captured requests contain a canary token."""
        return [r for r in self._requests if r.contains_canary(token)]

    def check_any_canary(self, tokens: list[str]) -> dict[str, list[CanaryRequest]]:
        """Check multiple canary tokens at once."""
        hits: dict[str, list[CanaryRequest]] = {}
        for token in tokens:
            matching = self.check_canary(token)
            if matching:
                hits[token] = matching
        return hits

    def clear(self) -> None:
        """Clear all captured requests."""
        self._requests.clear()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming HTTP connection."""
        try:
            # Read the request
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                writer.close()
                return

            request_text = request_line.decode("utf-8", errors="replace").strip()
            parts = request_text.split(" ")
            method = parts[0] if parts else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"

            # Parse query parameters
            query_params: dict[str, str] = {}
            if "?" in path:
                path_part, query_string = path.split("?", 1)
                path = path_part
                for param in query_string.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        query_params[k] = v

            # Read headers
            headers: dict[str, str] = {}
            content_length = 0
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                header_text = header_line.decode("utf-8", errors="replace").strip()
                if not header_text:
                    break
                if ":" in header_text:
                    key, value = header_text.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
                    if key.strip().lower() == "content-length":
                        content_length = int(value.strip())

            # Read body
            body = ""
            if content_length > 0:
                body_bytes = await asyncio.wait_for(
                    reader.read(min(content_length, 65536)),
                    timeout=5.0,
                )
                body = body_bytes.decode("utf-8", errors="replace")

            # Get source info
            peername = writer.get_extra_info("peername")
            source_ip = peername[0] if peername else "unknown"

            # Record the request
            captured = CanaryRequest(
                timestamp=datetime.now(timezone.utc),
                method=method,
                path=path,
                query_params=query_params,
                headers=headers,
                body=body,
                source_ip=source_ip,
            )
            self._requests.append(captured)

            logger.warning(
                f"Canary hit: {method} {path} "
                f"params={query_params} body_len={len(body)} "
                f"from={source_ip}"
            )

            # Send response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 16\r\n"
                "Connection: close\r\n"
                "\r\n"
                '{"status": "ok"}'
            )
            writer.write(response.encode())
            await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def __aenter__(self) -> CanaryServer:
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.stop()
