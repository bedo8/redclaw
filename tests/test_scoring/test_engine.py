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


def test_empty_results():
    """No results = perfect score (nothing to penalize)."""
    scorer = ScoringEngine()
    score = scorer.score([])
    assert score["overall_score"] == 0.0
    assert score["total_attacks"] == 0


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
    assert len(dims) == 5
    pi_dim = next(d for d in dims if d["key"] == "prompt_injection")
    assert pi_dim["score"] == 100.0
    assert pi_dim["defended"] == 1
