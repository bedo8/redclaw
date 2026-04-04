"""Tests for the prompt injection attack module."""

from redclaw.attacks.prompt_injection import PromptInjectionModule


def test_module_properties():
    """Module has correct name, AATCK IDs, and description."""
    mod = PromptInjectionModule(enable_mutations=False)
    assert mod.name == "Prompt Injection"
    assert "AATCK-001" in mod.aatck_ids
    assert len(mod.description) > 0


def test_payloads_generated():
    """Module generates payloads from templates."""
    mod = PromptInjectionModule(enable_mutations=False)
    payloads = mod.payloads()
    assert len(payloads) >= 8  # At least one per technique
    for p in payloads:
        assert p.content
        assert p.technique_id.startswith("AATCK-001")
        assert p.canary_token


def test_payloads_with_mutations():
    """Mutations generate additional payload variants."""
    mod_no_mut = PromptInjectionModule(enable_mutations=False)
    mod_mut = PromptInjectionModule(enable_mutations=True)

    base_count = len(mod_no_mut.payloads())
    mut_count = len(mod_mut.payloads())

    assert mut_count > base_count
    mutated = [p for p in mod_mut.payloads() if p.mutated]
    assert len(mutated) > 0


def test_canary_tokens_unique():
    """Each payload should have a unique canary token."""
    mod = PromptInjectionModule(enable_mutations=False)
    payloads = mod.payloads()
    # Canaries are unique per template (not per payload mutation)
    canaries = {p.canary_token for p in payloads}
    assert len(canaries) >= 8
