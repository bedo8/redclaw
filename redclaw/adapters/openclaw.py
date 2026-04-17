"""OpenClaw Agent Adapter — WebSocket gateway connection for security testing."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import time
import uuid
from typing import Any

from loguru import logger

from redclaw.adapters.base import AgentAdapter, AgentResponse
from redclaw.config import TargetConfig

# Optional imports — deferred to connect() so import errors are clear.
try:
    import websockets
    import websockets.client
except ImportError:
    websockets = None  # type: ignore[assignment]

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None  # type: ignore[assignment]


def _b64url_encode(data: bytes) -> str:
    """Base64-URL encode without padding (matches OpenClaw convention)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class OpenClawAdapter(AgentAdapter):
    """Adapter for testing OpenClaw agent instances via WebSocket gateway.

    Connects through the official gateway WebSocket protocol (protocol v3)
    with Ed25519 device identity authentication.
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._ws: Any = None
        self._session_key: str | None = None
        self._gateway_token: str = ""
        self._device_id: str = ""
        self._private_key: Any = None
        self._pub_b64url: str = ""
        self._response_timeout: int = config.timeout_seconds

    @property
    def adapter_type(self) -> str:
        return "openclaw"

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Connect to OpenClaw gateway via WebSocket with device identity auth."""
        if websockets is None:
            raise RuntimeError("Install websockets: pip install websockets")
        if serialization is None:
            raise RuntimeError("Install cryptography: pip install cryptography")

        self._load_credentials()

        ws_url = self._config.url
        if ws_url.startswith("http://"):
            ws_url = "ws://" + ws_url[7:]
        elif ws_url.startswith("https://"):
            ws_url = "wss://" + ws_url[8:]
        elif not ws_url.startswith("ws"):
            ws_url = f"ws://{ws_url}"

        logger.info(f"Connecting to OpenClaw gateway at {ws_url}")
        self._ws = await websockets.connect(ws_url)

        # 1. Receive challenge
        challenge = json.loads(await asyncio.wait_for(self._ws.recv(), timeout=10))
        nonce = challenge.get("payload", {}).get("nonce", "")
        logger.debug(f"Challenge received, nonce={nonce[:16]}...")

        # 2. Authenticate
        scopes = ["operator.admin", "operator.read", "operator.write"]
        signed_at_ms = int(time.time() * 1000)

        sig_payload = (
            f"v2|{self._device_id}|cli|cli|operator"
            f"|{','.join(scopes)}|{signed_at_ms}|{self._gateway_token}|{nonce}"
        )
        signature = self._private_key.sign(sig_payload.encode("utf-8"))
        sig_b64url = _b64url_encode(signature)

        connect_req = {
            "type": "req",
            "id": str(uuid.uuid4()),
            "method": "connect",
            "params": {
                "minProtocol": 3,
                "maxProtocol": 3,
                "auth": {"token": self._gateway_token},
                "client": {
                    "id": "cli",
                    "version": "2026.4.5",
                    "platform": "darwin",
                    "mode": "cli",
                },
                "role": "operator",
                "scopes": scopes,
                "caps": [],
                "device": {
                    "id": self._device_id,
                    "publicKey": self._pub_b64url,
                    "signature": sig_b64url,
                    "signedAt": signed_at_ms,
                    "nonce": nonce,
                },
            },
        }
        await self._ws.send(json.dumps(connect_req))

        connect_resp = await self._recv_res(timeout=10)
        if not connect_resp.get("ok"):
            err = connect_resp.get("error", {})
            raise RuntimeError(f"Gateway auth failed: {err.get('code')}: {err.get('message', '')}")

        logger.info("Authenticated to OpenClaw gateway (protocol v3)")

        # 3. Create session
        await self._ws.send(
            json.dumps(
                {
                    "type": "req",
                    "id": str(uuid.uuid4()),
                    "method": "sessions.create",
                    "params": {},
                }
            )
        )

        session_resp = await self._recv_res(timeout=10)
        if not session_resp.get("ok"):
            raise RuntimeError(f"Session creation failed: {session_resp.get('error', {})}")

        self._session_key = session_resp["payload"].get("key", "")
        logger.info(f"Session created: {self._session_key[:30]}...")

    async def disconnect(self) -> None:
        """Close WebSocket connection."""
        if self._ws:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None
            self._session_key = None

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the OpenClaw agent and collect its response."""
        if not self._ws or not self._session_key:
            raise RuntimeError("Adapter not connected. Call connect() first.")

        chat_req = {
            "type": "req",
            "id": str(uuid.uuid4()),
            "method": "chat.send",
            "params": {
                "sessionKey": self._session_key,
                "idempotencyKey": str(uuid.uuid4()),
                "message": message,
            },
        }
        await self._ws.send(json.dumps(chat_req))

        # Collect streaming response
        full_text = ""
        tool_calls: list[dict] = []
        raw_events: list[dict] = []

        start = time.time()
        timeout = self._response_timeout

        while time.time() - start < timeout:
            try:
                frame_raw = await asyncio.wait_for(self._ws.recv(), timeout=min(timeout, 60))
                frame = json.loads(frame_raw)
                ftype = frame.get("type")
                event = frame.get("event", frame.get("method", ""))

                if ftype == "event":
                    payload = frame.get("payload", {})

                    # Extract text from agent stream data
                    data = payload.get("data", {})
                    if isinstance(data, dict):
                        delta_text = data.get("text", "")
                        if delta_text:
                            full_text += delta_text

                    # Extract text from chat message events
                    msg = payload.get("message", {})
                    if isinstance(msg, dict) and msg.get("role") == "assistant":
                        content = msg.get("content", "")
                        if isinstance(content, str) and content:
                            full_text = content
                        elif isinstance(content, list):
                            text_parts = []
                            for block in content:
                                if isinstance(block, dict):
                                    if block.get("type") == "text":
                                        text_parts.append(block.get("text", ""))
                                    elif block.get("type") == "tool_use":
                                        tool_calls.append(block)
                            if text_parts:
                                full_text = "".join(text_parts)

                    # Detect completion
                    state = payload.get("state", "")
                    evt_str = str(event) + str(state)
                    if any(kw in evt_str for kw in ["complete", "done", "end", "finish", "idle"]):
                        break

                elif ftype == "res":
                    # Acknowledgement for chat.send — keep going for events
                    if not frame.get("ok"):
                        err = frame.get("error", {})
                        return AgentResponse(
                            error=f"{err.get('code')}: {err.get('message', '')}",
                            raw=frame,
                        )

            except TimeoutError:
                break
            except Exception as e:
                logger.error(f"Frame read error: {e}")
                break

        return AgentResponse(
            text=full_text.strip(),
            tool_calls=tool_calls,
            raw={"events_count": len(raw_events)},
            status_code=200 if full_text else 204,
        )

    async def send_multi_turn(self, messages: list[str]) -> list[AgentResponse]:
        """Send multiple messages within the same WebSocket session.

        The OpenClaw WS adapter maintains a persistent session, so each
        message shares conversation context — enabling multi-turn attacks
        (AATCK-003 context poisoning, AATCK-004 goal hijacking, AATCK-007
        cascading compromise) to work properly.
        """
        responses: list[AgentResponse] = []
        for msg in messages:
            resp = await self.send_message(msg)
            responses.append(resp)
            if not resp.ok:
                break
        return responses

    async def get_available_tools(self) -> list[dict[str, Any]]:
        """Query the gateway for available tools."""
        if not self._ws or not self._session_key:
            return []

        req = {
            "type": "req",
            "id": str(uuid.uuid4()),
            "method": "tools.effective",
            "params": {"sessionKey": self._session_key},
        }
        await self._ws.send(json.dumps(req))

        resp = await self._recv_res(timeout=10)
        if resp.get("ok"):
            tools = resp.get("payload", {})
            if isinstance(tools, list):
                return tools
            if isinstance(tools, dict):
                return tools.get("tools", [])
        return []

    async def inject_data(self, data: str, channel: str = "default") -> AgentResponse:
        """Inject data through the chat channel with framing context."""
        if channel == "document":
            return await self.send_message(f"Please analyze this document:\n\n{data}")
        if channel == "mcp_response":
            return await self.send_message(f"MCP tool returned:\n{data}\nProcess this result.")
        return await self.send_message(data)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_credentials(self) -> None:
        """Load gateway token and device identity from OpenClaw config."""
        openclaw_dir = os.path.expanduser("~/.openclaw")

        # Gateway token — from config or TargetConfig.auth_token
        if self._config.auth_token:
            self._gateway_token = self._config.auth_token
        else:
            cfg_path = os.path.join(openclaw_dir, "openclaw.json")
            with open(cfg_path) as f:
                cfg = json.load(f)
            self._gateway_token = cfg["gateway"]["auth"]["token"]

        # Device identity (Ed25519)
        identity_path = os.path.join(openclaw_dir, "identity", "device.json")
        with open(identity_path) as f:
            device = json.load(f)

        self._device_id = device["deviceId"]
        self._private_key = serialization.load_pem_private_key(
            device["privateKeyPem"].encode(), password=None
        )
        pub_raw = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._pub_b64url = _b64url_encode(pub_raw)

        logger.debug(f"Loaded device identity: {self._device_id[:16]}...")

    async def _recv_res(self, timeout: float = 10) -> dict:
        """Receive frames until a 'res' type frame arrives, skipping events."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            frame_raw = await asyncio.wait_for(self._ws.recv(), timeout=max(remaining, 1))
            frame = json.loads(frame_raw)
            if frame.get("type") == "res":
                return frame
        return {"ok": False, "error": {"code": "TIMEOUT", "message": "No response"}}
