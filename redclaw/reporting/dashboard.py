"""RedClaw Dashboard — FastAPI web UI for viewing scan results."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

REPORTS_DIR = Path("reports")


def create_app(reports_dir: Path | None = None) -> FastAPI:
    """Create the FastAPI dashboard application."""

    app = FastAPI(title="RedClaw Dashboard", version="0.1.0")
    rd = reports_dir or REPORTS_DIR

    @app.get("/", response_class=HTMLResponse)
    async def index():
        """Serve the dashboard UI."""
        return _build_dashboard_html(rd)

    @app.get("/api/reports")
    async def list_reports():
        """List all available scan reports."""
        if not rd.exists():
            return []
        reports = []
        for f in sorted(rd.glob("redclaw_report_*.json"), reverse=True):
            try:
                data = json.loads(f.read_text())
                reports.append({
                    "filename": f.name,
                    "campaign": data.get("meta", {}).get("campaign", ""),
                    "target": data.get("meta", {}).get("target", ""),
                    "score": data.get("score", {}).get("overall_score", 0),
                    "grade": data.get("score", {}).get("grade", "?"),
                    "generated_at": data.get("meta", {}).get("generated_at", ""),
                    "total_attacks": data.get("score", {}).get("total_attacks", 0),
                })
            except (json.JSONDecodeError, KeyError):
                continue
        return reports

    @app.get("/api/reports/{filename}")
    async def get_report(filename: str):
        """Get a specific report's full data."""
        filepath = rd / filename
        if not filepath.exists() or not filepath.name.startswith("redclaw_report_"):
            return JSONResponse({"error": "Report not found"}, status_code=404)
        return json.loads(filepath.read_text())

    @app.get("/api/latest")
    async def get_latest():
        """Get the latest scan report."""
        latest = rd / "latest.json"
        if not latest.exists():
            return JSONResponse({"error": "No reports found"}, status_code=404)
        return json.loads(latest.read_text())

    return app


def _build_dashboard_html(reports_dir: Path) -> str:
    """Build the dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedClaw Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #000; color: #e6edf3;
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif;
    min-height: 100vh;
  }

  .header {
    padding: 20px 32px; border-bottom: 1px solid #1a1a1a;
    display: flex; align-items: center; gap: 16px;
  }
  .header h1 { font-size: 20px; font-weight: 800; }
  .header h1 span { color: #EF4444; }
  .header .subtitle { color: #6b7280; font-size: 12px; }

  .container { max-width: 1200px; margin: 0 auto; padding: 24px 32px; }

  .score-hero {
    text-align: center; padding: 40px;
    background: #0a0a0a; border: 1px solid #1a1a1a;
    border-radius: 16px; margin-bottom: 24px;
  }
  .score-hero .grade {
    font-size: 80px; font-weight: 900; line-height: 1;
  }
  .score-hero .score-num { font-size: 20px; color: #9ba4b0; margin-top: 8px; }
  .score-hero .campaign { color: #6b7280; font-size: 13px; margin-top: 8px; }

  .stats-row {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 12px; margin-bottom: 24px;
  }
  .stat {
    background: #0a0a0a; border: 1px solid #1a1a1a;
    border-radius: 12px; padding: 16px; text-align: center;
  }
  .stat .num { font-size: 24px; font-weight: 800; }
  .stat .label { color: #6b7280; font-size: 11px; margin-top: 4px; }

  h2 {
    font-size: 15px; font-weight: 700; margin-bottom: 12px;
    padding-bottom: 8px; border-bottom: 1px solid #1a1a1a;
  }

  .dims-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .dim-card {
    background: #0a0a0a; border: 1px solid #1a1a1a;
    border-radius: 12px; padding: 16px;
  }
  .dim-card .dim-name { font-size: 12px; color: #9ba4b0; margin-bottom: 8px; }
  .dim-card .dim-score { font-size: 28px; font-weight: 800; }
  .dim-card .dim-detail { font-size: 11px; color: #6b7280; margin-top: 4px; }

  table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
  th {
    text-align: left; padding: 8px 12px; font-size: 11px;
    text-transform: uppercase; letter-spacing: 1px;
    color: #6b7280; border-bottom: 1px solid #1a1a1a;
  }
  td { padding: 8px 12px; border-bottom: 1px solid #0d0d0d; font-size: 13px; }
  tr:hover { background: #0a0a0a; }

  .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
  .sev-CRITICAL { background: rgba(239,68,68,0.15); color: #EF4444; }
  .sev-HIGH { background: rgba(245,158,11,0.15); color: #F59E0B; }
  .sev-MEDIUM { background: rgba(59,130,246,0.15); color: #3B82F6; }
  .sev-LOW { background: rgba(45,212,191,0.15); color: #2DD4BF; }
  .sev-INFO { background: rgba(107,114,128,0.15); color: #6b7280; }

  .technique-id { color: #EF4444; font-family: monospace; font-size: 12px; }
  .evidence { color: #9ba4b0; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .remediation { color: #2DD4BF; font-size: 12px; max-width: 300px; }

  .reports-list { margin-bottom: 24px; }
  .report-item {
    display: flex; align-items: center; gap: 16px;
    padding: 12px 16px; background: #0a0a0a; border: 1px solid #1a1a1a;
    border-radius: 10px; margin-bottom: 8px; cursor: pointer;
    transition: border-color 0.2s;
  }
  .report-item:hover { border-color: #EF4444; }
  .report-item .ri-grade { font-size: 24px; font-weight: 900; width: 40px; }
  .report-item .ri-info { flex: 1; }
  .report-item .ri-campaign { font-weight: 600; font-size: 13px; }
  .report-item .ri-meta { color: #6b7280; font-size: 11px; }

  .empty { text-align: center; padding: 60px; color: #6b7280; }
  .empty code { color: #EF4444; background: #1a1a1a; padding: 4px 8px; border-radius: 4px; font-size: 12px; }

  .tabs { display: flex; gap: 4px; margin-bottom: 24px; }
  .tab {
    padding: 8px 16px; border-radius: 8px; font-size: 13px;
    cursor: pointer; border: 1px solid #1a1a1a; background: #0a0a0a;
    color: #9ba4b0; transition: all 0.2s;
  }
  .tab.active { background: #EF4444; color: #fff; border-color: #EF4444; }

  .footer { text-align: center; padding: 24px; color: #4b5563; font-size: 11px; border-top: 1px solid #1a1a1a; margin-top: 40px; }
</style>
</head>
<body>

<div class="header">
  <h1><span>RedClaw</span> Dashboard</h1>
  <div class="subtitle">Adversarial AI Agent Security Assessment</div>
</div>

<div class="container" id="app">
  <div class="empty" id="loading">Loading...</div>
</div>

<div class="footer">
  RedClaw v0.1.0 &middot; AATCK Framework
</div>

<script>
const app = document.getElementById('app');
let currentView = 'latest';
let allReports = [];
let currentReport = null;

async function init() {
  try {
    const [latestRes, reportsRes] = await Promise.all([
      fetch('/api/latest').then(r => r.ok ? r.json() : null),
      fetch('/api/reports').then(r => r.json()),
    ]);
    allReports = reportsRes;
    if (latestRes) {
      currentReport = latestRes;
      renderReport(latestRes);
    } else {
      renderEmpty();
    }
  } catch (e) {
    renderEmpty();
  }
}

function gradeColor(grade) {
  return { A: '#2DD4BF', B: '#3B82F6', C: '#F59E0B', D: '#EF4444', F: '#DC2626' }[grade] || '#888';
}

function renderReport(data) {
  const s = data.score;
  const m = data.meta;
  const findings = data.findings.filter(f => f.status === 'success');
  const defended = data.findings.filter(f => f.status === 'defended');

  let dimsHtml = '';
  for (const d of (s.dimensions || [])) {
    const c = d.score >= 75 ? '#2DD4BF' : d.score >= 50 ? '#F59E0B' : '#EF4444';
    dimsHtml += `<div class="dim-card">
      <div class="dim-name">${d.name}</div>
      <div class="dim-score" style="color:${c}">${d.skipped ? 'N/A' : Math.round(d.score)}</div>
      <div class="dim-detail">${d.attacks} attacks &middot; ${d.defended} defended</div>
    </div>`;
  }

  let findingsHtml = '';
  for (const f of findings) {
    findingsHtml += `<tr>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      <td class="technique-id">${f.technique_id}</td>
      <td>${f.technique_name}</td>
      <td class="evidence" title="${esc(f.evidence)}">${esc(f.evidence.slice(0, 80))}</td>
      <td class="remediation">${esc(f.remediation.slice(0, 100))}</td>
    </tr>`;
  }
  if (!findingsHtml) {
    findingsHtml = '<tr><td colspan="5" style="text-align:center;color:#2DD4BF;padding:24px">No successful attacks.</td></tr>';
  }

  let reportsListHtml = '';
  for (const r of allReports) {
    reportsListHtml += `<div class="report-item" onclick="loadReport('${r.filename}')">
      <div class="ri-grade" style="color:${gradeColor(r.grade)}">${r.grade}</div>
      <div class="ri-info">
        <div class="ri-campaign">${r.campaign}</div>
        <div class="ri-meta">${r.target} &middot; ${r.total_attacks} attacks &middot; ${r.generated_at.slice(0,10)}</div>
      </div>
    </div>`;
  }

  app.innerHTML = `
    <div class="tabs">
      <div class="tab active" onclick="init()">Latest</div>
      <div class="tab" onclick="renderAllReports()">All Reports</div>
    </div>

    <div class="score-hero">
      <div class="grade" style="color:${gradeColor(s.grade)}">${s.grade}</div>
      <div class="score-num">${Math.round(s.overall_score)} / 100</div>
      <div class="campaign">${m.campaign} &middot; ${m.target} &middot; ${(m.duration_seconds || 0).toFixed(1)}s</div>
    </div>

    <div class="stats-row">
      <div class="stat"><div class="num">${s.total_attacks}</div><div class="label">Total Attacks</div></div>
      <div class="stat"><div class="num" style="color:#2DD4BF">${s.total_defended}</div><div class="label">Defended</div></div>
      <div class="stat"><div class="num" style="color:#EF4444">${s.total_succeeded}</div><div class="label">Succeeded</div></div>
      <div class="stat"><div class="num" style="color:${gradeColor(s.grade)}">${s.grade}</div><div class="label">Grade</div></div>
    </div>

    <h2>Resilience Dimensions</h2>
    <div class="dims-grid">${dimsHtml}</div>

    <h2>Findings (${findings.length} successful attacks)</h2>
    <table>
      <thead><tr><th>Severity</th><th>AATCK ID</th><th>Technique</th><th>Evidence</th><th>Remediation</th></tr></thead>
      <tbody>${findingsHtml}</tbody>
    </table>

    ${allReports.length > 1 ? '<h2>Recent Reports</h2><div class="reports-list">' + reportsListHtml + '</div>' : ''}
  `;
}

function renderAllReports() {
  let html = '<div class="tabs"><div class="tab" onclick="init()">Latest</div><div class="tab active">All Reports</div></div>';
  html += '<h2>All Reports</h2><div class="reports-list">';
  for (const r of allReports) {
    html += `<div class="report-item" onclick="loadReport('${r.filename}')">
      <div class="ri-grade" style="color:${gradeColor(r.grade)}">${r.grade}</div>
      <div class="ri-info">
        <div class="ri-campaign">${r.campaign} — Score: ${Math.round(r.score)}</div>
        <div class="ri-meta">${r.target} &middot; ${r.total_attacks} attacks &middot; ${r.generated_at.slice(0,10)}</div>
      </div>
    </div>`;
  }
  html += '</div>';
  app.innerHTML = html;
}

async function loadReport(filename) {
  const data = await fetch('/api/reports/' + filename).then(r => r.json());
  if (data.error) return;
  currentReport = data;
  renderReport(data);
}

function renderEmpty() {
  app.innerHTML = `<div class="empty">
    <p style="font-size:16px;margin-bottom:16px">No scan results yet.</p>
    <p>Run your first scan:</p>
    <p style="margin-top:8px"><code>redclaw scan --target http://your-agent:port</code></p>
  </div>`;
}

function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

init();
</script>
</body>
</html>"""


def run_dashboard(port: int = 8200, reports_dir: str = "reports") -> None:
    """Start the dashboard server."""
    import uvicorn
    app = create_app(Path(reports_dir))
    uvicorn.run(app, host="127.0.0.1", port=port)
