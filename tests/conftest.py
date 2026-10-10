"""Shared test fixtures for RedClaw tests."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from redclaw.attacks.base import AttackResult, AttackStatus, Severity


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory):
    """Keep the developer's real environment and .env out of every test."""
    for var in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "REDCLAW_AUTH_TOKEN",
        "REDCLAW_ANTHROPIC_API_KEY",
        "REDCLAW_ANTHROPIC_BASE_URL",
        "REDCLAW_CLAUDE_MODEL",
        "REDCLAW_LOG_LEVEL",
    ):
        monkeypatch.delenv(var, raising=False)
    # pydantic-settings reads ./.env; run from an empty directory.
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))


@pytest.fixture
def sample_target_config():
    from redclaw.config import AdapterType, TargetConfig

    return TargetConfig(url="http://127.0.0.1:9999", adapter=AdapterType.HTTP)


@pytest.fixture
def sample_campaign_config():
    from redclaw.config import CampaignConfig, CampaignPhase

    return CampaignConfig(
        name="Test Campaign",
        description="Unit test campaign",
        phases=[
            CampaignPhase(
                name="Prompt Injection",
                attack_modules=["prompt_injection"],
                timeout_seconds=30,
            )
        ],
        max_total_attacks=10,
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class JsonServer:
    """Tiny threaded HTTP server whose behaviour is a Python callable.

    ``handler(method, path, headers, body) -> (status, payload)`` where
    payload is JSON-serialisable or ``str`` (sent as text/plain).
    """

    def __init__(self, handler: Callable[[str, str, dict[str, str], Any], tuple[int, Any]]):
        self.requests: list[dict[str, Any]] = []
        outer = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _do(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body: Any = json.loads(raw) if raw else None
                except ValueError:
                    body = raw.decode(errors="replace")
                headers = {k.lower(): v for k, v in self.headers.items()}
                outer.requests.append(
                    {"method": self.command, "path": self.path, "headers": headers, "body": body}
                )
                status, payload = handler(self.command, self.path, headers, body)
                if isinstance(payload, str):
                    data, ctype = payload.encode(), "text/plain"
                else:
                    data, ctype = json.dumps(payload).encode(), "application/json"
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _do  # noqa: N815
            do_POST = _do  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def json_server() -> Iterator[Callable[..., JsonServer]]:
    servers: list[JsonServer] = []

    def make(handler: Callable[[str, str, dict[str, str], Any], tuple[int, Any]]) -> JsonServer:
        srv = JsonServer(handler)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


@pytest.fixture
def mock_agent_url() -> Iterator[str]:
    """The bundled vulnerable mock agent on a free loopback port."""
    from redclaw.mock_services.mock_agent import serve_in_thread

    server, _ = serve_in_thread(port=0)
    host, port = server.server_address[:2]
    yield f"http://{host!s}:{port}"
    server.shutdown()
    server.server_close()


def make_result(
    aatck_id: str = "AATCK-001",
    technique_id: str = "AATCK-001.T01",
    status: AttackStatus = AttackStatus.SUCCESS,
    severity: Severity = Severity.HIGH,
    **kw: Any,
) -> AttackResult:
    return AttackResult(
        module_name=kw.pop("module_name", "Prompt Injection"),
        aatck_id=aatck_id,
        technique_id=technique_id,
        technique_name=kw.pop("technique_name", "Direct instruction override"),
        status=status,
        severity=severity,
        **kw,
    )


def make_campaign_result(results: list[AttackResult], **kw: Any) -> Any:
    from redclaw.core.engine import CampaignResult
    from redclaw.core.scheduler import PhaseResult

    return CampaignResult(
        campaign_name=kw.get("campaign_name", "unit-test"),
        target_url=kw.get("target_url", "http://agent.example.com"),
        adapter_type=kw.get("adapter_type", "http"),
        phase_results=[PhaseResult(phase_name="Phase 1", attack_results=results)],
        completed_at=datetime.now(UTC),
    )
