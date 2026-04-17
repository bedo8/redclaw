"""Payload generator — creates attack payloads from templates with mutations."""

from __future__ import annotations

from redclaw.attacks.base import Payload
from redclaw.payloads.mutations import apply_mutations


def generate_payloads(
    templates: list[dict],
    canary_prefix: str = "REDCLAW",
    enable_mutations: bool = True,
    mutations_per_payload: int = 2,
) -> list[Payload]:
    """Generate payloads from templates with optional mutations.

    Args:
        templates: List of dicts with keys: content, technique_id, description.
        canary_prefix: Prefix for canary tokens.
        enable_mutations: Whether to create mutated variants.
        mutations_per_payload: How many mutation variants per template.

    Returns:
        List of Payload objects (originals + mutations).
    """
    import uuid

    payloads: list[Payload] = []

    for i, tmpl in enumerate(templates):
        canary = f"{canary_prefix}_CANARY_{uuid.uuid4().hex[:8].upper()}"
        content = tmpl["content"].replace("{CANARY}", canary)

        # Original payload
        payloads.append(
            Payload(
                content=content,
                technique_id=tmpl.get("technique_id", ""),
                canary_token=canary,
                description=tmpl.get("description", f"Payload {i + 1}"),
            )
        )

        # Mutated variants
        if enable_mutations:
            mutations = apply_mutations(content, count=mutations_per_payload)
            for mutated_content, mutation_type in mutations:
                payloads.append(
                    Payload(
                        content=mutated_content,
                        technique_id=tmpl.get("technique_id", ""),
                        canary_token=canary,
                        description=f"{tmpl.get('description', 'Payload')} [{mutation_type.value}]",
                        mutated=True,
                        mutation_type=mutation_type.value,
                    )
                )

    return payloads
