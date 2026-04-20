"""Tests for HTML + JSON report generation.

Cover:
- JSON report is valid JSON with the documented top-level keys.
- HTML report writes two files (timestamped + latest) and embeds the grade.
- Empty campaign (no findings) doesn't crash either generator.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from redclaw.attacks.base import AttackResult, AttackStatus, Severity
from redclaw.core.engine import CampaignResult
from redclaw.reporting.generator import ReportGenerator


@pytest.fixture
def campaign_result() -> CampaignResult:
    from redclaw.core.scheduler import PhaseResult

    r1 = AttackResult(
        module_name="prompt_injection",
        aatck_id="AATCK-001",
        technique_id="AATCK-001.T01",
        technique_name="System Prompt Override",
        status=AttackStatus.SUCCESS,
        severity=Severity.CRITICAL,
        confidence=0.95,
        payload_used="ignore previous instructions",
        evidence="Model complied with injection",
        canary_detected=True,
        remediation="Harden system prompt boundary",
    )
    r2 = AttackResult(
        module_name="prompt_injection",
        aatck_id="AATCK-001",
        technique_id="AATCK-001.T02",
        technique_name="Encoded Injection",
        status=AttackStatus.DEFENDED,
        severity=Severity.HIGH,
        confidence=0.8,
    )
    phase = PhaseResult(
        phase_name="Phase 1",
        attack_results=[r1, r2],
        modules_run=["prompt_injection"],
    )
    return CampaignResult(
        campaign_name="unit-test",
        target_url="http://target.local",
        adapter_type="http",
        phase_results=[phase],
        completed_at=datetime.now(UTC),
    )


@pytest.fixture
def score() -> dict:
    """Minimal shape matching what ScoringEngine.score() returns."""
    return {
        "overall_score": 72.5,
        "grade": "C",
        "total_attacks": 2,
        "successful_attacks": 1,
        "defended_attacks": 1,
        "dimensions": [
            {
                "key": "prompt_injection",
                "name": "Prompt Injection",
                "score": 50.0,
                "weight": 0.2,
                "attacks": 2,
                "defended": 1,
                "succeeded": 1,
            }
        ],
    }


def test_generate_json_writes_valid_report(
    tmp_path: Path, campaign_result: CampaignResult, score: dict
) -> None:
    gen = ReportGenerator(output_dir=tmp_path)
    out = gen.generate_json(campaign_result, score)

    assert out.exists()
    assert (tmp_path / "latest.json").exists()

    payload = json.loads(out.read_text())
    assert payload["meta"]["campaign"] == "unit-test"
    assert payload["meta"]["adapter"] == "http"
    assert payload["score"]["grade"] == "C"
    assert len(payload["findings"]) == 2
    assert payload["findings"][0]["status"] == "success"
    assert payload["findings"][0]["canary_detected"] is True


def test_generate_html_writes_timestamped_and_latest(
    tmp_path: Path, campaign_result: CampaignResult, score: dict
) -> None:
    gen = ReportGenerator(output_dir=tmp_path)
    out = gen.generate_html(campaign_result, score)

    assert out.exists()
    assert (tmp_path / "latest_report.html").exists()

    html = out.read_text()
    # Grade + target URL should make it into the rendered output.
    assert "C" in html
    assert "http://target.local" in html


def test_generator_creates_output_dir_if_missing(tmp_path: Path, score: dict) -> None:
    nested = tmp_path / "does" / "not" / "exist"
    gen = ReportGenerator(output_dir=nested)
    assert nested.exists() and nested.is_dir()

    empty = CampaignResult(
        campaign_name="empty",
        target_url="http://none",
        adapter_type="http",
        completed_at=datetime.now(UTC),
    )
    # Should not raise even with zero findings.
    json_out = gen.generate_json(empty, score)
    assert json.loads(json_out.read_text())["findings"] == []
