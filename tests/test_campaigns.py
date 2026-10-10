"""Campaign loading: built-ins ship as package data, names resolve strictly."""

from __future__ import annotations

from pathlib import Path

import pytest

from redclaw.campaigns import (
    CampaignLoadError,
    CampaignNotFoundError,
    builtin_campaign_names,
    list_campaigns,
    load_builtin_campaign,
    load_campaign_file,
    resolve_campaign,
)
from redclaw.config import AdapterType

EXPECTED_BUILTINS = {
    "quick_prompt_injection",
    "full_soc_assessment",
    "mcp_security_audit",
    "openclaw_pentest",
}


def test_builtins_are_package_resources() -> None:
    assert EXPECTED_BUILTINS <= set(builtin_campaign_names())


@pytest.mark.parametrize("name", sorted(EXPECTED_BUILTINS))
def test_every_builtin_loads_and_validates(name: str) -> None:
    campaign = load_builtin_campaign(name)
    assert campaign.phases
    assert all(phase.attack_modules for phase in campaign.phases)


def test_builtin_fields_round_trip() -> None:
    mcp = load_builtin_campaign("mcp_security_audit")
    assert mcp.target_adapter is AdapterType.MCP
    assert mcp.max_total_attacks == 100
    quick = load_builtin_campaign("quick_prompt_injection")
    assert quick.phases[0].max_concurrent == 5


def test_resolve_by_name(tmp_path: Path) -> None:
    campaign = resolve_campaign("quick_prompt_injection", search_dirs=[tmp_path])
    assert campaign.name == "Quick Prompt Injection Scan"


def test_resolve_by_path(tmp_path: Path) -> None:
    path = tmp_path / "custom.yaml"
    path.write_text(
        "name: Custom\nphases:\n  - name: P1\n    attack_modules: [goal_hijacking]\n",
        encoding="utf-8",
    )
    campaign = resolve_campaign(str(path))
    assert campaign.name == "Custom"
    assert campaign.phases[0].attack_modules == ["goal_hijacking"]


def test_local_campaign_dir_shadows_builtin(tmp_path: Path) -> None:
    (tmp_path / "quick_prompt_injection.yaml").write_text(
        "name: Local Override\nphases:\n  - name: P\n    attack_modules: [tool_abuse]\n",
        encoding="utf-8",
    )
    campaign = resolve_campaign("quick_prompt_injection", search_dirs=[tmp_path])
    assert campaign.name == "Local Override"


def test_unknown_name_raises_with_available_list(tmp_path: Path) -> None:
    with pytest.raises(CampaignNotFoundError, match="quick_prompt_injection"):
        resolve_campaign("definitely_not_a_campaign", search_dirs=[tmp_path])


def test_missing_yaml_path_raises() -> None:
    with pytest.raises(CampaignNotFoundError):
        resolve_campaign("/nonexistent/dir/campaign.yaml")


def test_unknown_attack_module_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "name: Bad\nphases:\n  - name: P\n    attack_modules: [not_a_module]\n",
        encoding="utf-8",
    )
    with pytest.raises(CampaignLoadError, match="not_a_module"):
        load_campaign_file(path)


def test_schema_errors_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("name: Bad\n", encoding="utf-8")  # no phases
    with pytest.raises(CampaignLoadError, match="invalid campaign"):
        load_campaign_file(path)


def test_non_mapping_rejected(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(CampaignLoadError, match="mapping"):
        load_campaign_file(path)


def test_invalid_yaml_rejected(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("name: [unclosed\n", encoding="utf-8")
    with pytest.raises(CampaignLoadError, match="invalid YAML"):
        load_campaign_file(path)


def test_list_campaigns_includes_local_and_skips_invalid(tmp_path: Path) -> None:
    (tmp_path / "mine.yaml").write_text(
        "name: Mine\ndescription: local one\nphases:\n"
        "  - name: P\n    attack_modules: [prompt_injection]\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.yaml").write_text("nope: true\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")
    infos = list_campaigns(search_dirs=[tmp_path])
    keys = {i.key: i for i in infos}
    assert "mine" in keys and keys["mine"].source.endswith("mine.yaml")
    assert "broken" not in keys
    assert keys["quick_prompt_injection"].source == "built-in"
