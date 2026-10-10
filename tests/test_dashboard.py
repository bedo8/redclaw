"""Dashboard API: path containment, listing, and XSS-safe rendering."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from redclaw.reporting.dashboard import create_app, safe_report_path


@pytest.fixture
def reports(tmp_path: Path) -> Path:
    d = tmp_path / "reports"
    d.mkdir()
    doc = {
        "meta": {"campaign": "<b>c</b>", "target": "http://t", "generated_at": "2026-10-01T00:00"},
        "score": {"overall_score": 50.0, "grade": "D", "total_attacks": 2},
        "findings": [],
    }
    (d / "redclaw_report_20261001_000000.json").write_text(json.dumps(doc))
    (d / "latest.json").write_text(json.dumps(doc))
    (d / "redclaw_report_broken.json").write_text("{not json")
    (tmp_path / "redclaw_report_outside.json").write_text(json.dumps(doc))
    return d


def test_safe_report_path_containment(reports: Path) -> None:
    assert safe_report_path(reports, "redclaw_report_20261001_000000.json") is not None
    for bad in (
        "../redclaw_report_outside.json",
        "..%2Fredclaw_report_outside.json",
        "/etc/passwd",
        "latest.json",  # not a timestamped report
        "redclaw_report_x.html",
        "redclaw_report_missing.json",
        "sub/redclaw_report_20261001_000000.json",
    ):
        assert safe_report_path(reports, bad) is None, bad


def test_safe_report_path_rejects_symlink_escape(reports: Path) -> None:
    link = reports / "redclaw_report_link.json"
    try:
        os.symlink(reports.parent / "redclaw_report_outside.json", link)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert safe_report_path(reports, link.name) is None


def test_api_endpoints(reports: Path) -> None:
    client = TestClient(create_app(reports))

    listing = client.get("/api/reports").json()
    assert [r["filename"] for r in listing] == ["redclaw_report_20261001_000000.json"]
    assert listing[0]["grade"] == "D"

    assert client.get("/api/reports/redclaw_report_20261001_000000.json").status_code == 200
    assert client.get("/api/reports/..%2Fredclaw_report_outside.json").status_code == 404
    assert client.get("/api/reports/redclaw_report_broken.json").status_code == 422
    assert client.get("/api/latest").json()["score"]["grade"] == "D"
    assert client.get("/api/info").json()["reports_dir"] == str(reports)


def test_api_empty_dir(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path / "missing"))
    assert client.get("/api/reports").json() == []
    assert client.get("/api/latest").status_code == 404


def test_index_has_csp_and_escapes_all_interpolations(reports: Path) -> None:
    resp = TestClient(create_app(reports)).get("/")
    assert resp.status_code == 200
    assert "default-src 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    page = resp.text
    # esc() must handle the single quote too.
    assert '.replace(/\'/g, "&#39;")' in page
    # No inline onclick handlers built from data.
    assert "onclick=" not in page
    # Every ${...} interpolation of report data goes through esc()/num()/a constant.
    safe_literals = {
        "findings.length",
        'active === "latest"',
        'active === "all"',
        "dims",
        "rows",
        's.overall_score == null ? "" : " / 100"',
    }
    for expr in re.findall(r"\$\{(.*?)\}(?=[^}]|$)", page):
        expr = expr.strip()
        if expr in safe_literals or expr.startswith(
            ("tabs(", "reportList()", "allReports.length > 1")
        ):
            continue
        assert expr.startswith(("esc(", "scoreClass(")), expr
