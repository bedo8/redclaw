"""Tests for the Typer CLI, including end-to-end scans against the bundled
mock agent on a loopback port."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from redclaw.cli import app

runner = CliRunner(env={"COLUMNS": "200"})


def test_root_help_renders() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "RedClaw" in result.stdout
    # Both sub-apps must be discoverable.
    assert "attacks" in result.stdout
    assert "campaigns" in result.stdout


def test_attacks_list_shows_builtin_modules() -> None:
    result = runner.invoke(app, ["attacks", "list"])
    assert result.exit_code == 0
    # These two modules must always ship.
    assert "prompt_injection" in result.stdout
    assert "tool_abuse" in result.stdout


def test_campaigns_list_does_not_crash() -> None:
    # Even with zero campaigns in CWD the table should still render.
    result = runner.invoke(app, ["campaigns", "list"])
    assert result.exit_code == 0
    assert "Campaigns" in result.stdout


def test_campaigns_list_shows_builtins() -> None:
    result = runner.invoke(app, ["campaigns", "list"])
    assert result.exit_code == 0
    assert "quick_prompt_injection" in result.stdout
    assert "built-in" in result.stdout


def test_scan_unknown_campaign_errors_instead_of_falling_back() -> None:
    result = runner.invoke(
        app, ["scan", "--target", "http://127.0.0.1:9", "--campaign", "no_such_campaign"]
    )
    assert result.exit_code == 1
    assert "unknown campaign" in result.stdout


# --- scan / report end to end -----------------------------------------------


def _scan(*args: str) -> Any:
    return runner.invoke(app, ["scan", *args], catch_exceptions=False)


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.startswith("redclaw ")


def test_scan_mock_agent_writes_all_formats(mock_agent_url: str, tmp_path: Path) -> None:
    out = tmp_path / "reports"
    result = _scan(
        "-t",
        mock_agent_url,
        "-c",
        "quick_prompt_injection",
        "-o",
        str(out),
        "-f",
        "all",
        "--no-mutations",
    )
    assert result.exit_code == 0, result.stdout
    assert "Resilience Score" in result.stdout
    for name in ("latest.json", "latest_report.html", "latest.sarif", "latest.junit.xml"):
        assert (out / name).is_file(), name
    doc = json.loads((out / "latest.json").read_text())
    assert doc["meta"]["version"]
    assert doc["findings"][0]["owasp_llm"]


def test_scan_fail_on_findings(mock_agent_url: str, tmp_path: Path) -> None:
    result = _scan(
        "-t",
        mock_agent_url,
        "-o",
        str(tmp_path),
        "-f",
        "json",
        "--no-mutations",
        "--fail-on-findings",
        "--no-canary",
    )
    assert result.exit_code == 3


def test_scan_unreachable_target_exits_2(tmp_path: Path) -> None:
    from tests.conftest import free_port

    result = _scan(
        "-t",
        f"http://127.0.0.1:{free_port()}",
        "-o",
        str(tmp_path),
        "-f",
        "json",
        "--no-mutations",
        "--no-canary",
        "--timeout",
        "2",
    )
    assert result.exit_code == 2
    assert "inconclusive" in result.stdout
    doc = json.loads((tmp_path / "latest.json").read_text())
    assert doc["score"]["grade"] == "N/A"


def test_scan_rejects_bad_format_and_adapter(tmp_path: Path) -> None:
    assert _scan("-t", "http://x", "-f", "pdf").exit_code == 1
    assert _scan("-t", "http://x", "-a", "carrier-pigeon").exit_code == 1


def test_scan_auth_token_from_env(json_server, tmp_path: Path, monkeypatch) -> None:
    srv = json_server(lambda *a: (200, {"response": "no"}))
    monkeypatch.setenv("REDCLAW_AUTH_TOKEN", "env-token-xyz")
    result = _scan(
        "-t",
        srv.url,
        "-o",
        str(tmp_path),
        "-f",
        "json",
        "--no-mutations",
        "--no-canary",
    )
    assert result.exit_code == 0, result.stdout
    assert srv.requests[0]["headers"]["authorization"] == "Bearer env-token-xyz"
    # The configured secret never lands in the report, even if echoed back.
    assert "env-token-xyz" not in (tmp_path / "latest.json").read_text()


def test_report_rerenders_saved_json(mock_agent_url: str, tmp_path: Path) -> None:
    src = tmp_path / "scan"
    _scan("-t", mock_agent_url, "-o", str(src), "-f", "json", "--no-mutations")
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["report", "-i", str(src / "latest.json"), "-o", str(out), "-f", "sarif,junit,html"]
    )
    assert result.exit_code == 0, result.stdout
    assert json.loads((out / "latest.sarif").read_text())["version"] == "2.1.0"
    assert (out / "latest.junit.xml").exists()
    assert (out / "latest_report.html").exists()


def test_report_errors(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["report", "-i", str(tmp_path / "nope.json")])
    assert missing.exit_code == 1
    bad = tmp_path / "bad.json"
    bad.write_text('{"x": 1}')
    assert runner.invoke(app, ["report", "-i", str(bad)]).exit_code == 1
    assert runner.invoke(app, ["report", "-i", str(bad), "-f", "pdf"]).exit_code == 1


def test_dashboard_without_extra_explains(monkeypatch) -> None:
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *a: None if name == "fastapi" else real(name, *a)
    )
    result = runner.invoke(app, ["dashboard"])
    assert result.exit_code == 1
    assert "redclaw[dashboard]" in result.stdout


def test_dashboard_starts_uvicorn(monkeypatch, tmp_path: Path) -> None:
    calls: dict[str, Any] = {}
    monkeypatch.setattr(
        "redclaw.reporting.dashboard.run_dashboard",
        lambda **kw: calls.update(kw),
    )
    result = runner.invoke(app, ["dashboard", "-p", "8765", "-r", str(tmp_path)])
    assert result.exit_code == 0, result.stdout
    assert calls == {"port": 8765, "reports_dir": str(tmp_path)}


def test_scan_with_seed_is_reproducible(mock_agent_url: str, tmp_path: Path) -> None:
    def score(run: str) -> dict:
        out = tmp_path / run
        result = _scan(
            "-t", mock_agent_url, "-o", str(out), "-f", "json", "--seed", "7", "--no-canary"
        )
        assert result.exit_code == 0, result.stdout
        return json.loads((out / "latest.json").read_text())["score"]

    first, second = score("a"), score("b")
    assert first["total_attacks"] > 0
    assert first["total_succeeded"] == second["total_succeeded"]
    assert first["overall_score"] == second["overall_score"]
