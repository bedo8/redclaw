"""Tests for the Typer CLI — exercises `attacks list`, `campaigns list`, and
the campaign-path resolver. `scan` and `dashboard` are not covered here because
they start a real engine / HTTP server."""

from __future__ import annotations

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
