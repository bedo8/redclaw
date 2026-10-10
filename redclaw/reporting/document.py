"""The report document: one JSON-serialisable dict every output format renders.

``build_document`` turns a campaign result plus its score into this dict.
The JSON report *is* the document, which is what lets ``redclaw report``
re-render an old scan as HTML, SARIF or JUnit without re-running it.

All free text that came back from the target (evidence, payload echoes) is
redacted here, before anything touches disk.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from redclaw.config import ReportConfig
from redclaw.reporting.redaction import redact
from redclaw.scoring.aatck import (
    ALL_TECHNIQUES,
    ATLAS_VERSION,
    OWASP_LLM_VERSION,
    framework_mappings,
)
from redclaw.version import __version__

SCHEMA_VERSION = "2"


def _strip_userinfo(url: str) -> str:
    """Drop ``user:password@`` from URL-shaped targets."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.scheme or "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _iso(value: Any) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else value


def build_document(
    campaign_result: Any,
    score: dict[str, Any],
    report_config: ReportConfig | None = None,
    secrets: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the canonical report document for a finished campaign."""
    cfg = report_config or ReportConfig()
    secrets = [s for s in secrets if s]

    def clean(text: str) -> str:
        return redact(text or "", secrets)

    findings: list[dict[str, Any]] = []
    for r in campaign_result.all_results:
        technique = ALL_TECHNIQUES.get(r.technique_id)
        mappings = framework_mappings(r.technique_id)
        findings.append(
            {
                "attack_id": r.attack_id,
                "module": r.module_name,
                "aatck_id": r.aatck_id,
                "technique_id": r.technique_id,
                "technique": technique.name if technique else r.technique_id,
                "technique_name": r.technique_name,
                "status": r.status.value,
                "severity": r.severity.value,
                "confidence": r.confidence,
                "canary_detected": r.canary_detected,
                "evidence": clean(r.evidence) if cfg.include_evidence else "",
                "remediation": r.remediation,
                "payload": clean(r.payload_used) if cfg.include_payloads else "",
                "timestamp": _iso(r.timestamp),
                "owasp_llm": mappings["owasp_llm"],
                "mitre_atlas": mappings["mitre_atlas"],
                "out_of_band": r.metadata.get("out_of_band", []),
            }
        )

    metadata = getattr(campaign_result, "metadata", {}) or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "meta": {
            "tool": "RedClaw",
            "version": __version__,
            "generated_at": datetime.now(UTC).isoformat(),
            "campaign": campaign_result.campaign_name,
            "target": clean(_strip_userinfo(campaign_result.target_url)),
            "adapter": campaign_result.adapter_type,
            "started_at": _iso(getattr(campaign_result, "started_at", None)),
            "completed_at": _iso(getattr(campaign_result, "completed_at", None)),
            "duration_seconds": campaign_result.duration_seconds,
            "error": clean(str(metadata["error"])) if metadata.get("error") else None,
            "frameworks": {"owasp_llm": OWASP_LLM_VERSION, "mitre_atlas": ATLAS_VERSION},
        },
        "score": score,
        "findings": findings,
    }


def validate_document(doc: Any) -> dict[str, Any]:
    """Light structural check for documents loaded from disk."""
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise ValueError("not a RedClaw JSON report (missing 'findings' list)")
    doc.setdefault("meta", {})
    doc.setdefault("score", {})
    for f in doc["findings"]:
        mappings = framework_mappings(f.get("technique_id", ""))
        f.setdefault("owasp_llm", mappings["owasp_llm"])
        f.setdefault("mitre_atlas", mappings["mitre_atlas"])
        tech = ALL_TECHNIQUES.get(f.get("technique_id", ""))
        f.setdefault("technique", tech.name if tech else f.get("technique_id", ""))
        f.setdefault("status", "defended")
        f.setdefault("severity", "MEDIUM")
    return doc


__all__ = ["SCHEMA_VERSION", "build_document", "validate_document"]
