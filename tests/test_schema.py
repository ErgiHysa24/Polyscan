"""The JSON files polyscan writes match the published schemas (docs/schema): the contract other tools,
such as WatchDog, import against. If a field is added or changed, this fails until the schema says so."""

import json
from pathlib import Path

import pytest

from polyscan import cli
from polyscan.models import ERROR, OK, SKIPPED, Finding, Severity, ToolResult
from polyscan.report import to_json
from polyscan.scanner import ScanResult

jsonschema = pytest.importorskip("jsonschema")
ROOT = Path(__file__).parent.parent
FIX = Path(__file__).parent / "fixtures"
SCAN = json.loads((ROOT / "docs" / "schema" / "polyscan-scan.schema.json").read_text(encoding="utf-8"))
RISK = json.loads((ROOT / "docs" / "schema" / "polyscan-risk.schema.json").read_text(encoding="utf-8"))

FINDINGS = [
    Finding("bandit", Severity.HIGH, "B608", "SQL built from text", "app/db.py", 4, "code", "python", "q = 'x' + y", "CWE-89"),
    Finding("osv-scanner", Severity.CRITICAL, "GHSA-jfh8-c2jp-5v3q", "log4j-core 2.14.1: CVE-2021-44228", "java/pom.xml", 0, "dependency", "java"),
    Finding("gitleaks", Severity.HIGH, "generic-api-key", "secret", "conf.py", 1, "secret", "", "[secret redacted]"),
    Finding("db-config", Severity.HIGH, "polyscan-db-weak-password", "weak", ".env", 1, "config", "database", "POSTGRES_PASSWORD=[redacted]", "CWE-1393"),
    Finding("trivy", Severity.CRITICAL, "CVE-2022-0001", "python:3.9.0-slim: libssl 1.1: x. Fixed in: 1.2.", "Dockerfile", 1, "dependency", "docker"),
    Finding("zap", Severity.MEDIUM, "10038", "CSP missing", "http://localhost:5000/", 0, "runtime", "", "", "CWE-693"),
    Finding("ss", Severity.HIGH, "exposed-postgresql", "PostgreSQL is listening on 0.0.0.0:5432", "0.0.0.0:5432", 0, "runtime"),
]


def scan_report(tmp_path):
    tools = [ToolResult("bandit", OK, "via local", FINDINGS), ToolResult("semgrep", ERROR, "network down"), ToolResult("npm-audit", SKIPPED, "no lockfile")]
    result = ScanResult(".", {"python": 3}, tools, notes=["a note"])
    p = tmp_path / "scan.json"
    p.write_text(to_json(result), encoding="utf-8")
    return p


def test_scan_report_matches_its_schema(tmp_path):
    data = json.loads(scan_report(tmp_path).read_text())
    jsonschema.validate(data, SCAN)
    assert data["schema"] == "polyscan-scan/1"


def test_full_risk_report_matches_its_schema(tmp_path, capsys):
    scan = scan_report(tmp_path)
    decisions = tmp_path / "d.json"
    decisions.write_text(json.dumps({"version": 1, "decisions": [
        {"tool": "gitleaks", "file": "*", "decision": "false-positive", "owner": "Ann", "justification": "fake"},
        {"rule": "B608", "decision": "mitigate", "owner": "Bob", "due": "2000-01-01", "ticket": "#1"},
        {"rule": "10038", "decision": "accept", "owner": "Bob", "justification": "j", "expires": "2099-01-01"}]}))  # fmt: skip
    out = tmp_path / "risk.json"
    cli.main(["risk", str(scan), "--json", str(out), "--decisions", str(decisions), "--kev-file", str(FIX / "kev.json"),
              "--epss-file", str(FIX / "epss.json"), "--factors", str(ROOT / "examples" / "vulnerable-demo" / "polyscan-factors.json")])  # fmt: skip
    data = json.loads(out.read_text())
    jsonschema.validate(data, RISK)
    states = {r["state"] for r in data["risks"]}
    assert {"overdue", "accepted", "untreated"} <= states and data["risks"][0]["exploitation"]["kev"]  # every shape was exercised
    assert data["coverage_gaps"] and data["treatment"]["false_positives"]


def test_minimal_risk_report_matches_too(tmp_path, capsys):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"polyscan": "x", "root": ".", "findings": []}))
    out = tmp_path / "risk.json"
    cli.main(["risk", str(p), "--json", str(out)])
    jsonschema.validate(json.loads(out.read_text()), RISK)


def test_schemas_are_strict_so_drift_is_caught():
    bad = json.loads(to_json(ScanResult(".", {})))
    bad["new_field"] = 1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, SCAN)
