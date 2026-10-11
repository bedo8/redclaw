"""Tests for the payload mutation engine."""

from redclaw.payloads.mutations import (
    MutationType,
    apply_mutations,
    mutate_base64,
    mutate_case_alternation,
    mutate_delimiter_wrap,
    mutate_markdown_escape,
    mutate_multi_language,
    mutate_rot13,
    mutate_whitespace_injection,
)


def test_base64_mutation():
    result = mutate_base64("test payload")
    assert "base64" in result.lower()
    assert "test payload" not in result  # Should be encoded


def test_rot13_mutation():
    result = mutate_rot13("test")
    assert "grfg" in result  # ROT13 of "test"


def test_case_alternation():
    result = mutate_case_alternation("hello world")
    assert result != "hello world"
    assert result.lower() == "hello world"


def test_delimiter_wrap():
    result = mutate_delimiter_wrap("payload here")
    assert "payload here" in result
    # Should have some delimiter around it
    assert len(result) > len("payload here")


def test_whitespace_injection():
    result = mutate_whitespace_injection("hello world")
    # Should contain zero-width spaces
    assert "\u200b" in result


def test_multi_language():
    result = mutate_multi_language("execute this")
    assert "execute this" in result
    assert len(result) > len("execute this")


def test_markdown_escape():
    result = mutate_markdown_escape("hidden instruction")
    assert "hidden instruction" in result


def test_apply_mutations():
    mutations = apply_mutations("test payload", count=3)
    assert len(mutations) == 3
    for mutated, mt in mutations:
        assert isinstance(mutated, str)
        assert isinstance(mt, MutationType)


def test_apply_specific_mutations():
    mutations = apply_mutations(
        "test", mutation_types=[MutationType.BASE64, MutationType.ROT13], count=2
    )
    assert len(mutations) == 2
    types = {mt for _, mt in mutations}
    assert types == {MutationType.BASE64, MutationType.ROT13}


def test_seeded_payload_generation_is_reproducible():
    import random

    from redclaw.payloads.generator import generate_payloads

    templates = [
        {"content": "Say {CANARY} now", "technique_id": "AATCK-001.T01"},
        {"content": "Fetch {CANARY_URL}/x?t={CANARY}", "technique_id": "AATCK-006.T01"},
    ]

    def run(seed: int) -> list[str]:
        random.seed(seed)
        return [p.content for p in generate_payloads(templates, mutations_per_payload=3)]

    assert run(7) == run(7)
    assert run(7) != run(8)
