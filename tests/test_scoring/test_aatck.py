"""Tests for the AATCK taxonomy dataclasses."""

import pytest

from redclaw.scoring.aatck import (
    AATCK_REGISTRY,
    ALL_TECHNIQUES,
    get_class,
    get_technique,
)


def test_all_8_classes_registered():
    """All 8 AATCK classes should be in the registry."""
    assert len(AATCK_REGISTRY) == 8
    for i in range(1, 9):
        assert f"AATCK-00{i}" in AATCK_REGISTRY


def test_classes_have_techniques():
    """Each class has at least 3 techniques."""
    for cls in AATCK_REGISTRY.values():
        assert len(cls.techniques) >= 3, f"{cls.id} has only {len(cls.techniques)} techniques"


def test_technique_ids_unique():
    """All technique IDs are globally unique."""
    all_ids = list(ALL_TECHNIQUES.keys())
    assert len(all_ids) == len(set(all_ids))


def test_technique_ids_follow_pattern():
    """Technique IDs follow AATCK-NNN.TNN pattern."""
    import re
    pattern = re.compile(r"AATCK-\d{3}\.T\d{2}")
    for tid in ALL_TECHNIQUES:
        assert pattern.match(tid), f"Bad technique ID format: {tid}"


def test_get_class():
    cls = get_class("AATCK-001")
    assert cls.name == "Prompt Injection"


def test_get_class_not_found():
    with pytest.raises(KeyError):
        get_class("AATCK-999")


def test_get_technique():
    t = get_technique("AATCK-001.T01")
    assert t.name == "Direct Override"


def test_get_technique_not_found():
    with pytest.raises(KeyError):
        get_technique("AATCK-001.T99")


def test_total_technique_count():
    """Verify we have a good coverage of techniques."""
    assert len(ALL_TECHNIQUES) >= 30, f"Only {len(ALL_TECHNIQUES)} techniques total"
