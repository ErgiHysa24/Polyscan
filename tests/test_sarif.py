"""SARIF output: valid against the official OASIS schema, and a failed tool is visible in it."""

import json
from pathlib import Path

import pytest

from polyscan import cli
from polyscan.models import ERROR, OK, SKIPPED, Finding, Severity, ToolResult
from polyscan.sarif import to_sarif
from polyscan.scanner import ScanResult

SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))


def result():
    good = ToolResult("bandit", OK, "", [
        Finding("bandit", Severity.HIGH, "B301", "pickle <b>loads</b>", "./app/x.py", 7, "code", "python", cwe="CWE-502"),
        Finding("bandit", Severity.LOW, "B301", "pickle again", ".github/scripts/y.py", 0, "code", "python"),
        Finding("bandit", Severity.CRITICAL, "", "no rule id", "", 0, "secret"),
    ])  # fmt: skip
    bad = ToolResult("semgrep", ERROR, "network down")
    skip = ToolResult("npm-audit", SKIPPED, "no lockfile")
    return ScanResult(".", {"python": 2}, [good, bad, skip])


def test_valid_against_the_official_schema():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(json.loads(to_sarif(result())), SCHEMA)


def test_content():
    data = json.loads(to_sarif(result()))
    bandit, semgrep, npm = data["runs"]
    assert data["version"] == "2.1.0" and bandit["tool"]["driver"]["name"] == "bandit"
    first = bandit["results"][0]
    assert first["level"] == "error" and first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/x.py"
    assert first["locations"][0]["physicalLocation"]["region"] == {"startLine": 7}
    assert bandit["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/scripts/y.py"
    assert "region" not in bandit["results"][1]["locations"][0]["physicalLocation"]  # line 0 = unknown, never a fake line 1
    rule = bandit["tool"]["driver"]["rules"][0]
    assert rule["id"] == "B301" and rule["properties"]["security-severity"] == "8.0"  # highest of its results
    assert "external/cwe/cwe-502" in rule["properties"]["tags"]
    assert bandit["results"][2]["ruleId"] == "polyscan-finding" and bandit["results"][2]["locations"] == []
    # a failed tool is NOT a clean run
    assert semgrep["invocations"][0]["executionSuccessful"] is False and "network down" in semgrep["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
    assert npm["invocations"][0]["executionSuccessful"] is True and npm["results"] == []


def test_site_findings_keep_the_url():
    r = ScanResult("http://localhost:8000", {}, [ToolResult("zap", OK, "", [Finding("zap", Severity.MEDIUM, "10038", "CSP", "http://localhost:8000/a", 0, "runtime", cwe="CWE-693")])], kind="site")
    loc = json.loads(to_sarif(r))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc == {"artifactLocation": {"uri": "http://localhost:8000/a"}}


def test_cli_writes_sarif(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n")
    out = tmp_path / "r.sarif"
    monkeypatch.setattr(cli, "scan", lambda *a, **k: result())
    cli.main(["scan", str(tmp_path), "--sarif", str(out), "--fail-on", "none"])
    assert json.loads(out.read_text())["version"] == "2.1.0"
