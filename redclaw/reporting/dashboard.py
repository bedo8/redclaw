"""RedClaw Dashboard — a small FastAPI app for browsing saved JSON reports.

Requires the ``dashboard`` extra (``pip install 'redclaw[dashboard]'``).
Binds to 127.0.0.1 by default; reports can contain sensitive evidence.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from redclaw.version import __version__

REPORTS_DIR = Path("reports")
_REPORT_GLOB = "redclaw_report_*.json"


def _dashboard_html() -> str:
    return (
        resources.files("redclaw.reporting")
        .joinpath("templates/dashboard.html")
        .read_text(encoding="utf-8")
    )


def safe_report_path(reports_dir: Path, filename: str) -> Path | None:
    """Resolve ``filename`` inside ``reports_dir`` or return None.

    Rejects anything that escapes the directory after resolution (``..``,
    absolute paths, symlinks pointing elsewhere) and anything that is not a
    RedClaw JSON report.
    """
    base = reports_dir.resolve()
    candidate = (base / filename).resolve()
    if not candidate.is_relative_to(base) or candidate.parent != base:
        return None
    if not (candidate.name.startswith("redclaw_report_") and candidate.suffix == ".json"):
        return None
    return candidate if candidate.is_file() else None


def _summary(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    meta = data.get("meta", {}) if isinstance(data, dict) else {}
    score = data.get("score", {}) if isinstance(data, dict) else {}
    return {
        "filename": path.name,
        "campaign": meta.get("campaign", ""),
        "target": meta.get("target", ""),
        "score": score.get("overall_score"),
        "grade": score.get("grade", "?"),
        "generated_at": meta.get("generated_at", ""),
        "total_attacks": score.get("total_attacks", 0),
    }


def create_app(reports_dir: Path | None = None) -> Any:
    """Create the FastAPI dashboard application."""
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "The dashboard needs the 'dashboard' extra: pip install 'redclaw[dashboard]'"
        ) from exc

    app = FastAPI(title="RedClaw Dashboard", version=__version__)
    rd = reports_dir or REPORTS_DIR
    page = _dashboard_html()
    security_headers = {
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(page, headers=security_headers)

    @app.get("/api/info")
    async def info() -> dict[str, str]:
        return {"version": __version__, "reports_dir": str(rd)}

    @app.get("/api/reports")
    async def list_reports() -> list[dict[str, Any]]:
        if not rd.is_dir():
            return []
        summaries = (_summary(p) for p in sorted(rd.glob(_REPORT_GLOB), reverse=True))
        return [s for s in summaries if s is not None]

    @app.get("/api/reports/{filename}", response_model=None)
    async def get_report(filename: str) -> Any:
        path = safe_report_path(rd, filename)
        if path is None:
            return JSONResponse({"error": "Report not found"}, status_code=404)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return JSONResponse({"error": "Report unreadable"}, status_code=422)

    @app.get("/api/latest", response_model=None)
    async def get_latest() -> Any:
        latest = rd / "latest.json"
        if not latest.is_file():
            return JSONResponse({"error": "No reports found"}, status_code=404)
        try:
            return json.loads(latest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return JSONResponse({"error": "Report unreadable"}, status_code=422)

    return app


def run_dashboard(port: int = 8200, reports_dir: str = "reports", host: str = "127.0.0.1") -> None:
    """Start the dashboard server."""
    import uvicorn

    uvicorn.run(create_app(Path(reports_dir)), host=host, port=port)
