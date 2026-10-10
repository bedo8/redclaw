"""Report generator — JSON, HTML, SARIF 2.1.0 and JUnit XML.

Every format is rendered from the same report document
(:mod:`redclaw.reporting.document`), and every file is created with
owner-only (``0600``) permissions because evidence can contain data the
target leaked.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from loguru import logger

from redclaw.config import ReportConfig, ReportFormat
from redclaw.reporting.document import build_document, validate_document
from redclaw.reporting.junit import build_junit
from redclaw.reporting.sarif import build_sarif
from redclaw.scoring.aatck import MITRE_ATLAS_TECHNIQUES, OWASP_LLM_TOP10_2025

_EXTENSIONS: dict[ReportFormat, str] = {
    ReportFormat.JSON: "json",
    ReportFormat.HTML: "html",
    ReportFormat.SARIF: "sarif",
    ReportFormat.JUNIT: "junit.xml",
}
_LATEST: dict[ReportFormat, str] = {
    ReportFormat.JSON: "latest.json",
    ReportFormat.HTML: "latest_report.html",
    ReportFormat.SARIF: "latest.sarif",
    ReportFormat.JUNIT: "latest.junit.xml",
}

_env = Environment(
    loader=PackageLoader("redclaw.reporting", "templates"),
    autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def write_private(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` with 0600 permissions (also on overwrite)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, 0o600)


def parse_formats(value: str | Iterable[str]) -> list[ReportFormat]:
    """Parse ``"html,sarif"`` / ``["json"]`` / ``"all"`` / legacy ``"both"``."""
    items = value.split(",") if isinstance(value, str) else list(value)
    formats: list[ReportFormat] = []
    for raw in items:
        item = raw.strip().lower()
        if not item:
            continue
        if item == "all":
            expanded = list(ReportFormat)
        elif item == "both":
            expanded = [ReportFormat.HTML, ReportFormat.JSON]
        else:
            try:
                expanded = [ReportFormat(item)]
            except ValueError:
                valid = ", ".join([f.value for f in ReportFormat] + ["all"])
                raise ValueError(f"unknown report format '{item}' (choose from {valid})") from None
        formats.extend(f for f in expanded if f not in formats)
    if not formats:
        raise ValueError("no report format given")
    return formats


def _coverage(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.get("status") not in ("success", "partial", "defended"):
            continue
        for fid in [*f.get("owasp_llm", []), *f.get("mitre_atlas", [])]:
            name = OWASP_LLM_TOP10_2025.get(fid) or MITRE_ATLAS_TECHNIQUES.get(fid, "")
            row = rows.setdefault(fid, {"id": fid, "name": name, "evaluated": 0, "succeeded": 0})
            row["evaluated"] += 1
            if f.get("status") == "success":
                row["succeeded"] += 1
    return sorted(rows.values(), key=lambda r: (not r["id"].startswith("LLM"), r["id"]))


def render(doc: dict[str, Any], fmt: ReportFormat) -> str:
    """Render a report document in the given format."""
    if fmt is ReportFormat.JSON:
        return json.dumps(doc, indent=2, default=str)
    if fmt is ReportFormat.SARIF:
        return json.dumps(build_sarif(doc), indent=2, default=str)
    if fmt is ReportFormat.JUNIT:
        return build_junit(doc)
    findings = doc.get("findings", [])
    return _env.get_template("report.html.j2").render(
        meta=doc.get("meta", {}),
        score=doc.get("score", {}),
        failures=[f for f in findings if f.get("status") == "success"],
        coverage=_coverage(findings),
    )


class ReportGenerator:
    """Writes assessment reports to ``output_dir``."""

    def __init__(
        self,
        output_dir: Path | None = None,
        report_config: ReportConfig | None = None,
        secrets: Iterable[str] = (),
    ) -> None:
        self._output_dir = output_dir or Path("reports")
        self._output_dir.mkdir(parents=True, exist_ok=True)
        # Best effort: the directory may belong to someone else; files are still 0600.
        with contextlib.suppress(OSError):
            os.chmod(self._output_dir, 0o700)
        self._config = report_config or ReportConfig()
        self._secrets = [s for s in secrets if s]
        self._stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    def document(self, campaign_result: Any, score: dict[str, Any]) -> dict[str, Any]:
        """Build the (redacted) report document for a campaign result."""
        return build_document(campaign_result, score, self._config, self._secrets)

    def write(self, doc: dict[str, Any], fmt: ReportFormat) -> Path:
        """Render ``doc`` as ``fmt`` and write a timestamped copy plus a ``latest`` copy."""
        doc = validate_document(doc)
        content = render(doc, fmt)
        path = self._output_dir / f"redclaw_report_{self._stamp}.{_EXTENSIONS[fmt]}"
        write_private(path, content)
        write_private(self._output_dir / _LATEST[fmt], content)
        logger.info(f"{fmt.value} report written: {path}")
        return path

    def generate(
        self, campaign_result: Any, score: dict[str, Any], formats: Iterable[ReportFormat]
    ) -> dict[ReportFormat, Path]:
        """Write the campaign result in each requested format."""
        doc = self.document(campaign_result, score)
        return {fmt: self.write(doc, fmt) for fmt in formats}

    # Convenience wrappers kept for API compatibility.
    def generate_html(self, campaign_result: Any, score: dict[str, Any]) -> Path:
        return self.write(self.document(campaign_result, score), ReportFormat.HTML)

    def generate_json(self, campaign_result: Any, score: dict[str, Any]) -> Path:
        return self.write(self.document(campaign_result, score), ReportFormat.JSON)

    def generate_sarif(self, campaign_result: Any, score: dict[str, Any]) -> Path:
        return self.write(self.document(campaign_result, score), ReportFormat.SARIF)

    def generate_junit(self, campaign_result: Any, score: dict[str, Any]) -> Path:
        return self.write(self.document(campaign_result, score), ReportFormat.JUNIT)


__all__ = ["ReportGenerator", "parse_formats", "render", "write_private"]
