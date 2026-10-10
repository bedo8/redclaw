"""Tests for the scoring engine."""

from redclaw.attacks.base import AttackResult, AttackStatus, Severity
from redclaw.scoring.engine import ScoringEngine


def _make_result(
    aatck_id: str = "AATCK-001",
    status: AttackStatus = AttackStatus.DEFENDED,
    severity: Severity = Severity.HIGH,
) -> AttackResult:
    return AttackResult(
        module_name="test",
        aatck_id=aatck_id,
        technique_id=f"{aatck_id}.T01",
        status=status,
        severity=severity,
    )


def test_perfect_score():
    """All attacks defended = score 100, grade A."""
    results = [_make_result(status=AttackStatus.DEFENDED) for _ in range(10)]
    scorer = ScoringEngine()
    score = scorer.score(results)
    assert score["overall_score"] == 100.0
    assert score["grade"] == "A"


def test_all_failed():
    """All attacks succeeded = score 0, grade F."""
    results = [_make_result(status=AttackStatus.SUCCESS) for _ in range(10)]
    scorer = ScoringEngine()
    score = scorer.score(results)
    assert score["overall_score"] == 0.0
    assert score["grade"] == "F"


def test_mixed_results():
    """Mix of defended and succeeded gives a score between 0 and 100."""
    results = [
        _make_result(status=AttackStatus.DEFENDED),
        _make_result(status=AttackStatus.DEFENDED),
        _make_result(status=AttackStatus.SUCCESS),
        _make_result(status=AttackStatus.DEFENDED),
    ]
    scorer = ScoringEngine()
    score = scorer.score(results)
    assert 50 < score["overall_score"] < 100
    assert score["total_defended"] == 3
    assert score["total_succeeded"] == 1


def test_empty_results_are_not_tested():
    """No results = no evidence: score is None, grade N/A, not a fake 0 or 100."""
    scorer = ScoringEngine()
    score = scorer.score([])
    assert score["overall_score"] is None
    assert score["grade"] == "N/A"
    assert score["tested"] is False
    assert score["total_attacks"] == 0


def test_unreachable_target_is_not_an_f():
    """Regression: ERROR results used to count as attempted-not-defended, so an
    unreachable target scored F 0/100."""
    results = [_make_result(status=AttackStatus.ERROR) for _ in range(20)]
    score = ScoringEngine().score(results)
    assert score["overall_score"] is None
    assert score["grade"] == "N/A"
    assert score["tested"] is False
    assert score["total_errors"] == 20
    pi = next(d for d in score["dimensions"] if d["key"] == "prompt_injection")
    assert pi["score"] is None
    assert pi["status"] == "all_errors"
    assert pi["errors"] == 20
    assert pi["attacks"] == 0


def test_errors_are_excluded_from_denominator():
    """3 defended + 1 succeeded + 6 errors -> 75, not 30."""
    results = (
        [_make_result(status=AttackStatus.DEFENDED) for _ in range(3)]
        + [_make_result(status=AttackStatus.SUCCESS)]
        + [_make_result(status=AttackStatus.ERROR) for _ in range(6)]
    )
    score = ScoringEngine().score(results)
    assert score["overall_score"] == 75.0
    assert score["grade"] == "B"
    pi = next(d for d in score["dimensions"] if d["key"] == "prompt_injection")
    assert pi["attacks"] == 4
    assert pi["errors"] == 6


def test_skipped_results_are_not_scored():
    results = [
        _make_result(status=AttackStatus.SKIPPED),
        _make_result(status=AttackStatus.DEFENDED),
    ]
    score = ScoringEngine().score(results)
    assert score["overall_score"] == 100.0
    assert score["total_evaluated"] == 1


def test_partial_counts_as_not_defended():
    results = [
        _make_result(status=AttackStatus.PARTIAL),
        _make_result(status=AttackStatus.DEFENDED),
    ]
    score = ScoringEngine().score(results)
    assert score["overall_score"] == 50.0


def test_errored_dimension_does_not_drag_down_tested_one():
    """One dimension fully errored, another fully defended -> 100 (renormalised)."""
    results = [
        _make_result(aatck_id="AATCK-001", status=AttackStatus.DEFENDED),
        _make_result(aatck_id="AATCK-002", status=AttackStatus.ERROR),
    ]
    score = ScoringEngine().score(results)
    assert score["overall_score"] == 100.0
    ta = next(d for d in score["dimensions"] if d["key"] == "tool_abuse")
    assert ta["status"] == "all_errors"


def test_weighted_average_across_dimensions():
    from redclaw.config import ScoringWeights

    weights = ScoringWeights(prompt_injection=0.75, tool_abuse=0.25)
    results = [
        _make_result(aatck_id="AATCK-001", status=AttackStatus.DEFENDED),
        _make_result(aatck_id="AATCK-002", status=AttackStatus.SUCCESS),
    ]
    score = ScoringEngine(weights).score(results)
    assert score["overall_score"] == 75.0


def test_unknown_aatck_class_is_ignored():
    results = [_make_result(aatck_id="AATCK-999", status=AttackStatus.SUCCESS)]
    score = ScoringEngine().score(results)
    assert score["tested"] is False
    assert score["total_attacks"] == 1


def test_grade_boundaries():
    """Test grade boundary mapping."""
    scorer = ScoringEngine()
    assert scorer._grade(95) == "A"
    assert scorer._grade(90) == "A"
    assert scorer._grade(89) == "B"
    assert scorer._grade(75) == "B"
    assert scorer._grade(74) == "C"
    assert scorer._grade(60) == "C"
    assert scorer._grade(59) == "D"
    assert scorer._grade(40) == "D"
    assert scorer._grade(39) == "F"
    assert scorer._grade(0) == "F"


def test_dimensions_populated():
    """Score should include dimension breakdowns."""
    results = [_make_result(aatck_id="AATCK-001", status=AttackStatus.DEFENDED)]
    scorer = ScoringEngine()
    score = scorer.score(results)
    dims = score["dimensions"]
    assert len(dims) == 8
    pi_dim = next(d for d in dims if d["key"] == "prompt_injection")
    assert pi_dim["score"] == 100.0
    assert pi_dim["defended"] == 1
