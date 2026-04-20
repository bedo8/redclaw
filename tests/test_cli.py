"""Tests for the Typer CLI — exercises `attacks list`, `campaigns list`, and
the campaign-path resolver. `scan` and `dashboard` are not covered here because
they start a real engine / HTTP server."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from redclaw.cli import _resolve_campaign, app

runner = CliRunner()


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


def test_resolve_campaign_direct_yaml_path(tmp_path: Path) -> None:
    custom = tmp_path / "my-campaign.yaml"
    custom.write_text("name: custom\nphases: []\n")
    resolved = _resolve_campaign(str(custom))
    assert resolved == custom


def test_resolve_campaign_builtin_lookup() -> None:
    # `quick_prompt_injection` is the default campaign name and must resolve
    # to a built-in YAML file shipped with the package.
    resolved = _resolve_campaign("quick_prompt_injection")
    assert resolved is not None
    assert resolved.exists()
    assert resolved.suffix in (".yaml", ".yml")


def test_resolve_campaign_unknown_returns_none() -> None:
    assert _resolve_campaign("this_campaign_definitely_does_not_exist") is None
