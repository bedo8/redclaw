"""Payload generator — creates attack payloads from templates with mutations."""

from __future__ import annotations

from redclaw.attacks.base import DEFAULT_CANARY_URL, Payload, new_canary
from redclaw.payloads.mutations import apply_mutations


def fill_template(template: str, canary: str, canary_url: str = DEFAULT_CANARY_URL) -> str:
    """Substitute ``{CANARY}`` and ``{CANARY_URL}`` and unescape ``{{``/``}}``.

    Templates escape literal braces format-style (``{{"key": 1}}``), so the
    target receives real JSON rather than doubled braces.
    """
    return (
        template.replace("{CANARY_URL}", canary_url.rstrip("/"))
        .replace("{CANARY}", canary)
        .replace("{{", "{")
        .replace("}}", "}")
    )


def generate_payloads(
    templates: list[dict],
    canary_prefix: str = "REDCLAW",
    enable_mutations: bool = True,
    mutations_per_payload: int = 2,
    canary_url: str = DEFAULT_CANARY_URL,
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
    payloads: list[Payload] = []

    for i, tmpl in enumerate(templates):
        canary = new_canary(canary_prefix)
        content = fill_template(tmpl["content"], canary, canary_url)

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
