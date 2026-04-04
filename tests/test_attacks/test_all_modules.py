"""Tests for all 7 attack modules — validates structure and payloads."""

import pytest

from redclaw.attacks.prompt_injection import PromptInjectionModule
from redclaw.attacks.tool_abuse import ToolAbuseModule
from redclaw.attacks.context_poisoning import ContextPoisoningModule
from redclaw.attacks.goal_hijacking import GoalHijackingModule
from redclaw.attacks.mcp_exploitation import MCPExploitationModule
from redclaw.attacks.data_exfiltration import DataExfiltrationModule
from redclaw.attacks.cascading_compromise import CascadingCompromiseModule


ALL_MODULES = [
    (PromptInjectionModule, "AATCK-001", "Prompt Injection"),
    (ToolAbuseModule, "AATCK-002", "Tool Abuse"),
    (ContextPoisoningModule, "AATCK-003", "Context Poisoning"),
    (GoalHijackingModule, "AATCK-004", "Goal Hijacking"),
    (MCPExploitationModule, "AATCK-005", "MCP Exploitation"),
    (DataExfiltrationModule, "AATCK-006", "Data Exfiltration"),
    (CascadingCompromiseModule, "AATCK-007", "Cascading Compromise"),
]


@pytest.mark.parametrize("module_cls,expected_aatck,expected_name", ALL_MODULES)
def test_module_properties(module_cls, expected_aatck, expected_name):
    """Each module has correct AATCK ID and name."""
    mod = module_cls() if module_cls == ContextPoisoningModule else module_cls(enable_mutations=False)
    assert mod.name == expected_name
    assert expected_aatck in mod.aatck_ids
    assert len(mod.description) > 20


@pytest.mark.parametrize("module_cls,expected_aatck,expected_name", ALL_MODULES)
def test_module_has_payloads(module_cls, expected_aatck, expected_name):
    """Each module generates at least 3 payloads."""
    mod = module_cls() if module_cls == ContextPoisoningModule else module_cls(enable_mutations=False)
    payloads = mod.payloads()
    assert len(payloads) >= 3, f"{expected_name} only has {len(payloads)} payloads"


@pytest.mark.parametrize("module_cls,expected_aatck,expected_name", ALL_MODULES)
def test_payloads_have_canaries(module_cls, expected_aatck, expected_name):
    """Each payload has a canary token."""
    mod = module_cls() if module_cls == ContextPoisoningModule else module_cls(enable_mutations=False)
    for p in mod.payloads():
        assert p.canary_token, f"Payload missing canary: {p.description}"
        assert "CANARY" in p.canary_token


@pytest.mark.parametrize("module_cls,expected_aatck,expected_name", ALL_MODULES)
def test_payloads_have_technique_ids(module_cls, expected_aatck, expected_name):
    """Each payload maps to a technique ID."""
    mod = module_cls() if module_cls == ContextPoisoningModule else module_cls(enable_mutations=False)
    for p in mod.payloads():
        assert p.technique_id.startswith(expected_aatck), f"Bad technique ID: {p.technique_id}"
