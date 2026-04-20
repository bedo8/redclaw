"""Verify the Phase 2.2 public API surface is stable and importable."""

from __future__ import annotations

import inspect

import redclaw


def test_public_api_symbols_importable() -> None:
    """Every name in __all__ must be accessible on the top-level package."""
    for name in redclaw.__all__:
        assert hasattr(redclaw, name), f"redclaw.{name} missing despite being in __all__"


def test_run_campaign_is_coroutine_function() -> None:
    assert inspect.iscoroutinefunction(redclaw.run_campaign)


def test_target_and_campaign_aliases_resolve_to_config_models() -> None:
    from redclaw.config import CampaignConfig, TargetConfig

    assert redclaw.Target is TargetConfig
    assert redclaw.Campaign is CampaignConfig


def test_version_string_matches_package_metadata() -> None:
    assert isinstance(redclaw.__version__, str)
    # SemVer-ish sanity check — don't pin the exact value here so the
    # Phase 3 setuptools-scm switch doesn't break this test.
    assert redclaw.__version__.count(".") >= 1


def test_adapter_registry_reachable_from_top_level() -> None:
    # Importing `redclaw` must transitively populate the registry so that
    # library users don't need to know about `redclaw.adapters`.
    assert "http" in redclaw.list_adapters()
