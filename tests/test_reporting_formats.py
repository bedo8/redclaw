"""SARIF, JUnit, HTML escaping, redaction and file permissions."""

from __future__ import annotations

import json
import stat
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from redclaw.attacks.base import AttackStatus, Severity
from redclaw.config import ReportConfig, ReportFormat
from redclaw.reporting.document import build_document, validate_document
from redclaw.reporting.generator import ReportGenerator, parse_formats, render
from redclaw.reporting.junit import build_junit
from redclaw.reporting.redaction import redact
from redclaw.reporting.sarif import SARIF_VERSION, build_sarif
from redclaw.scoring.engine import ScoringEngine
from tests.conftest import make_campaign_result, make_result

XSS = "<script>alert('x')</script>\"'><img src=x onerror=alert(1)>"


@pytest.fixture
def mixed_doc() -> dict:
    results = [
        make_result(
            status=AttackStatus.SUCCESS,
            severity=Severity.CRITICAL,
            evidence="Response: key sk-ant-api03-abcdefghijklmnopqrstuvwx leaked",
            canary_detected=True,
            remediation="Fix it",
            payload_used="Ignore previous instructions",
        ),
        make_result(technique_id="AATCK-001.T02", status=AttackStatus.DEFENDED),
        make_result(technique_id="AATCK-001.T02", status=AttackStatus.PARTIAL),
        make_result(
            aatck_id="AATCK-002",
            technique_id="AATCK-002.T01",
            status=AttackStatus.ERROR,
            evidence="Connection failed",
        ),
        make_result(
            aatck_id="AATCK-002", technique_id="AATCK-002.T03", status=AttackStatus.SKIPPED
        ),
        make_result(technique_id="CUSTOM.T99", technique_name="custom thing"),
    ]
    cr = make_campaign_result(results)
    return build_document(cr, ScoringEngine().score(cr.all_results))


# --- SARIF ---------------------------------------------------------------------


def test_sarif_top_level_shape(mixed_doc: dict) -> None:
    sarif = build_sarif(mixed_doc)
    assert sarif["version"] == SARIF_VERSION == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    (run,) = sarif["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "RedClaw"
    assert driver["informationUri"].startswith("https://")
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sarif_rules_carry_framework_mappings(mixed_doc: dict) -> None:
    run = build_sarif(mixed_doc)["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    t01 = rules["AATCK-001.T01"]
    assert "LLM01:2025" in t01["properties"]["tags"]
    assert t01["properties"]["mitre_atlas"] == ["AML.T0051.000"]
    assert "OWASP LLM Top 10 (2025)" in t01["help"]["text"]
    assert float(t01["properties"]["security-severity"]) >= 7.0
    # Unknown technique still gets a usable rule.
    assert rules["CUSTOM.T99"]["shortDescription"]["text"] == "custom thing"


def test_sarif_results_kinds_levels_and_indexes(mixed_doc: dict) -> None:
    run = build_sarif(mixed_doc)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    kinds = [r["kind"] for r in run["results"]]
    assert kinds.count("fail") == 2  # T01 + custom
    assert kinds.count("pass") == 1
    assert kinds.count("review") == 1
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert res["partialFingerprints"]["redclawFinding/v1"]
        if res["kind"] == "pass":
            assert res["level"] == "none"
    critical = next(r for r in run["results"] if r["ruleId"] == "AATCK-001.T01")
    assert critical["level"] == "error"
    assert critical["properties"]["owasp_llm"] == ["LLM01:2025"]


def test_sarif_errors_become_notifications(mixed_doc: dict) -> None:
    run = build_sarif(mixed_doc)["runs"][0]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) == 1
    assert "Connection failed" in notes[0]["message"]["text"]
    assert all(r["ruleId"] != "AATCK-002.T01" for r in run["results"])


def test_sarif_untested_scan_marks_execution_unsuccessful() -> None:
    cr = make_campaign_result([make_result(status=AttackStatus.ERROR)])
    doc = build_document(cr, ScoringEngine().score(cr.all_results))
    run = build_sarif(doc)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["results"] == []


def test_sarif_validates_against_official_schema_if_available(mixed_doc: dict) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parent / "data" / "sarif-schema-2.1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = list(jsonschema.Draft4Validator(schema).iter_errors(build_sarif(mixed_doc)))
    assert errors == []


# --- JUnit ---------------------------------------------------------------------


def test_junit_structure(mixed_doc: dict) -> None:
    root = ET.fromstring(build_junit(mixed_doc))
    assert root.tag == "testsuites"
    assert root.get("tests") == "6"
    assert root.get("failures") == "3"  # 2 success + 1 partial
    assert root.get("errors") == "1"
    assert root.get("skipped") == "1"
    suites = {s.get("name"): s for s in root.findall("testsuite")}
    assert "AATCK-001 Prompt Injection" in suites
    pi = suites["AATCK-001 Prompt Injection"]
    failures = pi.findall("testcase/failure")
    assert failures and "LLM01:2025" in (failures[0].text or "")
    tool = suites["AATCK-002 Tool Abuse"]
    assert tool.find("testcase/error") is not None
    assert tool.find("testcase/skipped") is not None


# --- HTML ----------------------------------------------------------------------


def test_html_autoescapes_everything() -> None:
    result = make_result(
        module_name=XSS, technique_name=XSS, evidence=XSS, remediation=XSS, severity=Severity.HIGH
    )
    cr = make_campaign_result(
        [result], campaign_name=XSS, target_url=f"http://example.com/{XSS}", adapter_type=XSS
    )
    html = render(build_document(cr, ScoringEngine().score([result])), ReportFormat.HTML)
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "&#39;" in html or "&#x27;" in html


def test_html_shows_mappings_and_untested_banner() -> None:
    ok = make_campaign_result([make_result()])
    html = render(build_document(ok, ScoringEngine().score(ok.all_results)), ReportFormat.HTML)
    assert "LLM01:2025" in html and "AML.T0051.000" in html
    assert "Framework coverage" in html

    bad = make_campaign_result([make_result(status=AttackStatus.ERROR)])
    html = render(build_document(bad, ScoringEngine().score(bad.all_results)), ReportFormat.HTML)
    assert "Scan inconclusive" in html
    assert "not tested" in html


# --- Redaction -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        ("key sk-ant-api03-abcdefghijklmnopqrstuvwx", "abcdefghijklmnop"),
        ("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuv", "abcdefghijklmnop"),
        ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("ghp_" + "a" * 36, "a" * 36),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnop"),
        ('{"api_key": "hunter2hunter2"}', "hunter2"),
        ("password=correct-horse-battery", "correct-horse"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk", "eyJzdWIi"),
    ],
)
def test_redact_known_patterns(text: str, leaked: str) -> None:
    out = redact(text)
    assert leaked not in out
    assert "[REDACTED" in out


def test_redact_keeps_canaries_and_plain_text() -> None:
    text = "Token: REDCLAW_PI_CANARY_ABCD1234 and the token is fine"
    assert redact(text) == text
    assert redact("") == ""


def test_redact_configured_secret() -> None:
    assert "s3cr3t-value" not in redact("echo s3cr3t-value", secrets=["s3cr3t-value"])


def test_document_redacts_and_strips_userinfo() -> None:
    cr = make_campaign_result(
        [make_result(evidence="leak sk-ant-api03-abcdefghijklmnopqrstuvwx")],
        target_url="https://user:pass@agent.example.com/chat",
    )
    doc = build_document(cr, ScoringEngine().score(cr.all_results), secrets=["pass"])
    assert doc["meta"]["target"] == "https://agent.example.com/chat"
    assert "abcdefghijklmnop" not in doc["findings"][0]["evidence"]


def test_document_honours_report_config() -> None:
    cr = make_campaign_result([make_result(evidence="e", payload_used="p")])
    doc = build_document(
        cr,
        ScoringEngine().score(cr.all_results),
        ReportConfig(include_payloads=False, include_evidence=False),
    )
    assert doc["findings"][0]["payload"] == ""
    assert doc["findings"][0]["evidence"] == ""


def test_validate_document_backfills_old_reports() -> None:
    old = {"findings": [{"technique_id": "AATCK-006.T01", "status": "success"}]}
    doc = validate_document(old)
    assert doc["findings"][0]["owasp_llm"] == ["LLM07:2025"]
    with pytest.raises(ValueError):
        validate_document({"nope": 1})


# --- Generator -----------------------------------------------------------------


def test_parse_formats() -> None:
    assert parse_formats("html,sarif") == [ReportFormat.HTML, ReportFormat.SARIF]
    assert parse_formats("both") == [ReportFormat.HTML, ReportFormat.JSON]
    assert set(parse_formats("all")) == set(ReportFormat)
    assert parse_formats(["json", "json"]) == [ReportFormat.JSON]
    with pytest.raises(ValueError, match="unknown report format"):
        parse_formats("pdf")
    with pytest.raises(ValueError):
        parse_formats(" , ")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_reports_are_private(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    cr = make_campaign_result([make_result()])
    gen = ReportGenerator(output_dir=out)
    paths = gen.generate(cr, ScoringEngine().score(cr.all_results), list(ReportFormat))
    assert set(paths) == set(ReportFormat)
    for path in [*paths.values(), *out.glob("latest*")]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    sarif = json.loads((out / "latest.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert (out / "latest.junit.xml").read_text().startswith("<?xml")


def test_generator_wrappers(tmp_path: Path) -> None:
    cr = make_campaign_result([make_result()])
    score = ScoringEngine().score(cr.all_results)
    gen = ReportGenerator(output_dir=tmp_path)
    assert gen.generate_sarif(cr, score).suffix == ".sarif"
    assert gen.generate_junit(cr, score).name.endswith(".junit.xml")
