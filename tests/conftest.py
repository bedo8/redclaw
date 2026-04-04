"""Shared test fixtures for RedClaw tests."""

import pytest


@pytest.fixture
def sample_target_config():
    """Create a sample target config for testing."""
    from redclaw.config import AdapterType, TargetConfig
    return TargetConfig(url="http://localhost:9999", adapter=AdapterType.HTTP)


@pytest.fixture
def sample_campaign_config():
    """Create a sample campaign config for testing."""
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
