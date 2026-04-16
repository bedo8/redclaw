"""Report generator — HTML and JSON reports with AATCK mappings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger


class ReportGenerator:
    """Generates HTML and JSON security assessment reports."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self._output_dir = output_dir or Path("reports")
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate_html(self, campaign_result, score: dict[str, Any]) -> Path:
        """Generate a premium HTML report.

        Args:
            campaign_result: CampaignResult from engine.
            score: Score dict from ScoringEngine.

        Returns:
            Path to generated HTML file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"redclaw_report_{timestamp}.html"
        output_path = self._output_dir / filename

        html = self._build_html(campaign_result, score)
        output_path.write_text(html, encoding="utf-8")

        # Also save as latest
        latest_path = self._output_dir / "latest_report.html"
        latest_path.write_text(html, encoding="utf-8")

        logger.info(f"HTML report generated: {output_path}")
        return output_path

    def generate_json(self, campaign_result, score: dict[str, Any]) -> Path:
        """Generate a JSON report for machine consumption.

        Args:
            campaign_result: CampaignResult from engine.
            score: Score dict from ScoringEngine.

        Returns:
            Path to generated JSON file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"redclaw_report_{timestamp}.json"
        output_path = self._output_dir / filename

        report_data = {
            "meta": {
                "tool": "RedClaw",
                "version": "0.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "campaign": campaign_result.campaign_name,
                "target": campaign_result.target_url,
                "adapter": campaign_result.adapter_type,
                "duration_seconds": campaign_result.duration_seconds,
            },
            "score": score,
            "findings": [
                {
                    "attack_id": r.attack_id,
                    "module": r.module_name,
                    "aatck_id": r.aatck_id,
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "confidence": r.confidence,
                    "canary_detected": r.canary_detected,
                    "evidence": r.evidence,
                    "remediation": r.remediation,
                    "payload": r.payload_used,
                    "timestamp": r.timestamp.isoformat(),
                }
                for r in campaign_result.all_results
            ],
        }

        output_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        # Also save as latest
        latest_path = self._output_dir / "latest.json"
        latest_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        logger.info(f"JSON report generated: {output_path}")
        return output_path

    def _build_html(self, result, score: dict[str, Any]) -> str:
        """Build the full HTML report string."""
        grade = score["grade"]
        overall = score["overall_score"]

        grade_color = {
            "A": "#2DD4BF", "B": "#3B82F6", "C": "#F59E0B", "D": "#EF4444", "F": "#DC2626",
        }.get(grade, "#888")

        # Build dimension rows
        dim_rows = ""
        for dim in score.get("dimensions", []):
            if dim.get("skipped"):
                dim_rows += f"""
                <tr class="dim-row">
                    <td>{dim['name']}</td>
                    <td class="score-cell" style="color:#6b7280">&mdash;</td>
                    <td>{dim['weight']:.0%}</td>
                    <td>0</td>
                    <td>&mdash;</td>
                    <td>&mdash;</td>
                </tr>"""
            else:
                sc = dim['score']
                sc_color = "#2DD4BF" if sc >= 75 else "#F59E0B" if sc >= 50 else "#EF4444"
                dim_rows += f"""
                <tr class="dim-row">
                    <td>{dim['name']}</td>
                    <td class="score-cell" style="color:{sc_color}">{sc:.0f}</td>
                    <td>{dim['weight']:.0%}</td>
                    <td>{dim['attacks']}</td>
                    <td style="color:#2DD4BF">{dim['defended']}</td>
                    <td style="color:#EF4444">{dim['succeeded']}</td>
                </tr>"""

        # Build findings rows
        findings_rows = ""
        for r in result.all_results:
            if not r.succeeded:
                continue
            sev_class = r.severity.value.lower()
            findings_rows += f"""
            <tr>
                <td><span class="sev-badge sev-{sev_class}">{r.severity.value}</span></td>
                <td class="technique-id">{r.technique_id}</td>
                <td>{r.technique_name}</td>
                <td class="evidence-cell">{_escape(r.evidence[:150])}</td>
                <td class="remediation-cell">{_escape(r.remediation[:150])}</td>
            </tr>"""

        if not findings_rows:
            findings_rows = """
            <tr><td colspan="5" style="text-align:center;color:#2DD4BF;padding:24px">
                No successful attacks — agent defended all payloads.
            </td></tr>"""

        # Defended count
        defended_count = score.get("total_defended", 0)
        succeeded_count = score.get("total_succeeded", 0)
        total_count = score.get("total_attacks", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedClaw Security Assessment Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #000; color: #e6edf3;
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif;
    padding: 40px; max-width: 1000px; margin: 0 auto;
    font-size: 14px; line-height: 1.6;
  }}

  .header {{
    text-align: center; margin-bottom: 40px;
    padding-bottom: 24px; border-bottom: 1px solid #1a1a1a;
  }}
  .header h1 {{ font-size: 28px; font-weight: 800; }}
  .header h1 span {{ color: #EF4444; }}
  .header .subtitle {{ color: #6b7280; font-size: 13px; margin-top: 4px; }}

  .score-card {{
    text-align: center; padding: 32px;
    background: #0a0a0a; border: 1px solid #1a1a1a;
    border-radius: 16px; margin-bottom: 32px;
  }}
  .score-card .grade {{
    font-size: 72px; font-weight: 900; line-height: 1;
  }}
  .score-card .score-num {{
    font-size: 24px; color: #9ba4b0; margin-top: 8px;
  }}
  .score-card .meta-row {{
    display: flex; justify-content: center; gap: 32px;
    margin-top: 16px; color: #6b7280; font-size: 13px;
  }}
  .score-card .meta-row span {{ color: #e6edf3; font-weight: 600; }}

  .stats-grid {{
    display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 12px; margin-bottom: 32px;
  }}
  .stat-box {{
    background: #0a0a0a; border: 1px solid #1a1a1a;
    border-radius: 12px; padding: 20px; text-align: center;
  }}
  .stat-box .num {{ font-size: 28px; font-weight: 800; }}
  .stat-box .label {{ color: #6b7280; font-size: 12px; margin-top: 4px; }}

  h2 {{
    font-size: 16px; font-weight: 700; margin-bottom: 16px;
    padding-bottom: 8px; border-bottom: 1px solid #1a1a1a;
  }}

  table {{ width: 100%; border-collapse: collapse; margin-bottom: 32px; }}
  th {{
    text-align: left; padding: 10px 12px; font-size: 11px;
    text-transform: uppercase; letter-spacing: 1px;
    color: #6b7280; border-bottom: 1px solid #1a1a1a;
  }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #0d0d0d; font-size: 13px; }}
  .dim-row:hover, tr:hover {{ background: #0a0a0a; }}
  .score-cell {{ font-weight: 700; font-size: 15px; }}
  .technique-id {{ color: #EF4444; font-family: monospace; font-size: 12px; }}
  .evidence-cell {{ color: #9ba4b0; font-size: 12px; }}
  .remediation-cell {{ color: #2DD4BF; font-size: 12px; }}

  .sev-badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 10px; font-weight: 700; letter-spacing: 0.5px;
  }}
  .sev-critical {{ background: rgba(239,68,68,0.15); color: #EF4444; }}
  .sev-high {{ background: rgba(245,158,11,0.15); color: #F59E0B; }}
  .sev-medium {{ background: rgba(59,130,246,0.15); color: #3B82F6; }}
  .sev-low {{ background: rgba(45,212,191,0.15); color: #2DD4BF; }}
  .sev-info {{ background: rgba(107,114,128,0.15); color: #6b7280; }}

  .footer {{
    text-align: center; padding-top: 24px;
    border-top: 1px solid #1a1a1a; color: #4b5563;
    font-size: 11px; margin-top: 40px;
  }}

  @media print {{
    body {{ background: #fff; color: #000; }}
    .score-card, .stat-box {{ border-color: #ccc; background: #f9f9f9; }}
    .sev-critical {{ color: red; }} .sev-high {{ color: orange; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1><span>RedClaw</span> Security Assessment Report</h1>
  <div class="subtitle">
    AATCK-Based Adversarial AI Agent Assessment &middot;
    {result.campaign_name} &middot;
    {datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M UTC")}
  </div>
</div>

<div class="score-card">
  <div class="grade" style="color:{grade_color}">{grade}</div>
  <div class="score-num">{overall:.0f} / 100</div>
  <div class="meta-row">
    <div>Target: <span>{_escape(result.target_url)}</span></div>
    <div>Adapter: <span>{result.adapter_type}</span></div>
    <div>Duration: <span>{result.duration_seconds:.1f}s</span></div>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-box">
    <div class="num" style="color:#e6edf3">{total_count}</div>
    <div class="label">Total Attacks</div>
  </div>
  <div class="stat-box">
    <div class="num" style="color:#2DD4BF">{defended_count}</div>
    <div class="label">Defended</div>
  </div>
  <div class="stat-box">
    <div class="num" style="color:#EF4444">{succeeded_count}</div>
    <div class="label">Succeeded</div>
  </div>
</div>

<h2>Resilience Dimensions</h2>
<table>
  <thead>
    <tr>
      <th>Dimension</th><th>Score</th><th>Weight</th>
      <th>Attacks</th><th>Defended</th><th>Succeeded</th>
    </tr>
  </thead>
  <tbody>{dim_rows}
  </tbody>
</table>

<h2>Findings</h2>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>AATCK ID</th><th>Technique</th>
      <th>Evidence</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>{findings_rows}
  </tbody>
</table>

<div class="footer">
  RedClaw v0.1.0 &middot; Adversarial AI Agent Red Team Framework &middot;
  AATCK Framework v1.0
</div>

</body>
</html>"""


def _escape(text: str) -> str:
    """Basic HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
