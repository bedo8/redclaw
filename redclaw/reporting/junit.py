"""JUnit XML output for CI systems.

One ``testsuite`` per AATCK class, one ``testcase`` per attack:

* SUCCESS / PARTIAL -> ``<failure>`` (the agent was compromised)
* ERROR             -> ``<error>``   (the attack could not run)
* SKIPPED           -> ``<skipped>``
* DEFENDED          -> passing test case
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any

from redclaw.scoring.aatck import AATCK_REGISTRY


def build_junit(doc: dict[str, Any]) -> str:
    """Render a report document as a JUnit XML string."""
    meta = doc.get("meta", {})
    findings = doc.get("findings", [])

    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_class[f.get("aatck_id") or "AATCK-UNKNOWN"].append(f)

    root = ET.Element(
        "testsuites",
        name=f"RedClaw: {meta.get('campaign', 'scan')}",
        tests=str(len(findings)),
        failures=str(sum(1 for f in findings if f.get("status") in ("success", "partial"))),
        errors=str(sum(1 for f in findings if f.get("status") == "error")),
        skipped=str(sum(1 for f in findings if f.get("status") == "skipped")),
        time=f"{float(meta.get('duration_seconds') or 0):.3f}",
    )

    for class_id in sorted(by_class):
        cases = by_class[class_id]
        aatck_class = AATCK_REGISTRY.get(class_id)
        suite = ET.SubElement(
            root,
            "testsuite",
            name=f"{class_id} {aatck_class.name}" if aatck_class else class_id,
            tests=str(len(cases)),
            failures=str(sum(1 for f in cases if f.get("status") in ("success", "partial"))),
            errors=str(sum(1 for f in cases if f.get("status") == "error")),
            skipped=str(sum(1 for f in cases if f.get("status") == "skipped")),
            timestamp=str(meta.get("started_at") or ""),
        )
        props = ET.SubElement(suite, "properties")
        ET.SubElement(props, "property", name="target", value=str(meta.get("target", "")))
        ET.SubElement(props, "property", name="adapter", value=str(meta.get("adapter", "")))

        for f in cases:
            tid = f.get("technique_id", "")
            case = ET.SubElement(
                suite,
                "testcase",
                classname=f"redclaw.{f.get('module') or class_id}",
                name=f"{tid} {f.get('technique_name') or f.get('technique', '')}".strip(),
            )
            status = f.get("status")
            mappings = ", ".join([*f.get("owasp_llm", []), *f.get("mitre_atlas", [])])
            detail = "\n".join(
                line
                for line in (
                    f"Evidence: {f.get('evidence', '')}" if f.get("evidence") else "",
                    f"Remediation: {f.get('remediation', '')}" if f.get("remediation") else "",
                    f"Mappings: {mappings}" if mappings else "",
                )
                if line
            )
            if status in ("success", "partial"):
                el = ET.SubElement(
                    case,
                    "failure",
                    message=f"{f.get('severity', 'MEDIUM')}: agent compromised ({status})",
                    type=tid or "AATCK",
                )
                el.text = detail
            elif status == "error":
                el = ET.SubElement(case, "error", message="attack could not run", type="error")
                el.text = f.get("evidence", "")
            elif status == "skipped":
                ET.SubElement(case, "skipped")

    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


__all__ = ["build_junit"]
