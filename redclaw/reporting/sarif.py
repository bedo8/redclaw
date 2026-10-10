"""SARIF 2.1.0 output.

Each AATCK technique that appears in the scan becomes a ``reportingDescriptor``
(rule) tagged with its OWASP LLM Top 10 (2025) and MITRE ATLAS IDs. Each
attack becomes a ``result``:

* SUCCESS  -> ``kind: fail``   (level from severity)
* PARTIAL  -> ``kind: review`` (level ``warning``)
* DEFENDED -> ``kind: pass``   (level ``none``)

ERROR and SKIPPED attacks are not results; they are reported as tool
execution notifications on the invocation, and the invocation is marked
unsuccessful when nothing could be evaluated.

The scanned artifact is the target agent, so results point at the target
URI rather than at a source file.
"""

from __future__ import annotations

import hashlib
from typing import Any

from redclaw.scoring.aatck import (
    ALL_TECHNIQUES,
    ATLAS_URL,
    MITRE_ATLAS_TECHNIQUES,
    OWASP_LLM_TOP10_2025,
    OWASP_LLM_URL,
    get_class,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/bedo8/redclaw"

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# GitHub code scanning reads properties.security-severity (0.0-10.0).
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "1.0",
}


def _rule(technique_id: str, fallback_name: str) -> dict[str, Any]:
    tech = ALL_TECHNIQUES.get(technique_id)
    if tech is None:
        return {
            "id": technique_id or "AATCK-UNKNOWN",
            "name": "".join(ch for ch in fallback_name.title() if ch.isalnum()) or "Unknown",
            "shortDescription": {"text": fallback_name or technique_id or "Unknown technique"},
            "properties": {"tags": ["security", "ai-agent"]},
        }

    aatck_class = get_class(technique_id.split(".")[0])
    owasp = [f"{i} {OWASP_LLM_TOP10_2025[i]}" for i in tech.owasp_llm]
    atlas = [f"{i} {MITRE_ATLAS_TECHNIQUES[i]}" for i in tech.atlas]
    mapping_lines = []
    if owasp:
        mapping_lines.append("OWASP LLM Top 10 (2025): " + "; ".join(owasp))
    if atlas:
        mapping_lines.append("MITRE ATLAS: " + "; ".join(atlas))
    remediation = "\n".join(f"- {r}" for r in aatck_class.remediation)
    help_text = f"{tech.description}\n\nRemediation:\n{remediation}"
    if mapping_lines:
        help_text += "\n\n" + "\n".join(mapping_lines)

    worst = aatck_class.severity_range[1].value
    return {
        "id": tech.id,
        "name": "".join(word.capitalize() for word in tech.name.replace("/", " ").split()),
        "shortDescription": {"text": f"{aatck_class.name}: {tech.name}"},
        "fullDescription": {"text": tech.description},
        "help": {"text": help_text},
        "helpUri": f"{INFORMATION_URI}/blob/main/docs/AATCK_FRAMEWORK.md",
        "defaultConfiguration": {"level": _LEVEL.get(worst, "warning")},
        "properties": {
            "tags": [
                "security",
                "ai-agent",
                aatck_class.id,
                *tech.owasp_llm,
                *tech.atlas,
            ],
            "aatck_class": aatck_class.id,
            "owasp_llm": list(tech.owasp_llm),
            "mitre_atlas": list(tech.atlas),
            "security-severity": _SECURITY_SEVERITY.get(worst, "5.5"),
        },
    }


def _result(finding: dict[str, Any], rule_index: int, target: str) -> dict[str, Any] | None:
    status = finding.get("status")
    severity = str(finding.get("severity", "MEDIUM")).upper()
    tid = finding.get("technique_id", "")
    if status == "success":
        kind, level = "fail", _LEVEL.get(severity, "warning")
        verb = "Attack succeeded"
    elif status == "partial":
        kind, level = "review", "warning"
        verb = "Partial indicators of compromise"
    elif status == "defended":
        kind, level = "pass", "none"
        verb = "Agent defended"
    else:
        return None

    label = finding.get("technique_name") or finding.get("technique") or tid
    text = f"{verb}: {tid} {label}."
    if finding.get("evidence"):
        text += f" Evidence: {finding['evidence'][:500]}"

    fingerprint = hashlib.sha256(
        f"{tid}\x00{finding.get('technique_name', '')}\x00{target}".encode()
    ).hexdigest()

    props: dict[str, Any] = {
        "attack_id": finding.get("attack_id"),
        "module": finding.get("module"),
        "severity": severity,
        "confidence": finding.get("confidence", 0.0),
        "canary_detected": bool(finding.get("canary_detected")),
        "owasp_llm": finding.get("owasp_llm", []),
        "mitre_atlas": finding.get("mitre_atlas", []),
    }
    if status == "success":
        props["security-severity"] = _SECURITY_SEVERITY.get(severity, "5.5")
    if finding.get("remediation"):
        props["remediation"] = finding["remediation"]

    return {
        "ruleId": tid or "AATCK-UNKNOWN",
        "ruleIndex": rule_index,
        "kind": kind,
        "level": level,
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": target or "unknown-target"}},
                "logicalLocations": [
                    {"name": finding.get("module") or "agent", "kind": "module"},
                ],
            }
        ],
        "partialFingerprints": {"redclawFinding/v1": fingerprint},
        "properties": props,
    }


def build_sarif(doc: dict[str, Any]) -> dict[str, Any]:
    """Render a report document as a SARIF 2.1.0 log (a JSON-ready dict)."""
    meta = doc.get("meta", {})
    findings = doc.get("findings", [])
    target = str(meta.get("target", ""))

    rule_ids: list[str] = []
    rule_names: dict[str, str] = {}
    for f in findings:
        tid = f.get("technique_id") or "AATCK-UNKNOWN"
        if tid not in rule_names:
            rule_ids.append(tid)
            known = tid in ALL_TECHNIQUES
            rule_names[tid] = (f.get("technique") if known else f.get("technique_name")) or tid
    rules = [_rule(tid, rule_names[tid]) for tid in rule_ids]
    index = {tid: i for i, tid in enumerate(rule_ids)}

    results = []
    notifications = []
    for f in findings:
        tid = f.get("technique_id") or "AATCK-UNKNOWN"
        res = _result(f, index[tid], target)
        if res is not None:
            results.append(res)
        elif f.get("status") == "error":
            notifications.append(
                {
                    "level": "warning",
                    "message": {"text": f"{tid}: attack could not run: {f.get('evidence', '')}"},
                    "descriptor": {"id": tid},
                }
            )

    score = doc.get("score", {})
    invocation: dict[str, Any] = {
        "executionSuccessful": bool(score.get("tested", bool(results))),
        "toolExecutionNotifications": notifications,
    }
    if meta.get("started_at"):
        invocation["startTimeUtc"] = meta["started_at"]
    if meta.get("completed_at"):
        invocation["endTimeUtc"] = meta["completed_at"]
    if meta.get("error"):
        invocation["exitCodeDescription"] = str(meta["error"])

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RedClaw",
                        "semanticVersion": str(meta.get("version", "0.0.0")).split("+")[0],
                        "version": str(meta.get("version", "0.0.0")),
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "automationDetails": {"id": f"redclaw/{meta.get('campaign', 'scan')}/"},
                "artifacts": [{"location": {"uri": target or "unknown-target"}}],
                "results": results,
                "properties": {
                    "campaign": meta.get("campaign"),
                    "adapter": meta.get("adapter"),
                    "overall_score": score.get("overall_score"),
                    "grade": score.get("grade"),
                    "frameworks": meta.get("frameworks", {}),
                    "references": {"owasp_llm": OWASP_LLM_URL, "mitre_atlas": ATLAS_URL},
                },
            }
        ],
    }


__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "build_sarif"]
