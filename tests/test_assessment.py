"""The assessment report: every section is there, failures and missing authorization are visible, text is escaped."""

import json
from pathlib import Path

from polyscan import cli

FIX = Path(__file__).parent / "fixtures"


def write(tmp_path, name, findings, tools):
    p = tmp_path / name
    p.write_text(json.dumps({"polyscan": "x", "root": ".", "kind": "folder", "tools": tools, "findings": findings}))
    return str(p)


F = [
    {"tool": "osv-scanner", "severity": "critical", "rule": "GHSA-jfh8-c2jp-5v3q", "message": "log4j-core 2.14.1: CVE-2021-44228 <script>x</script>", "file": "java/pom.xml", "line": 0, "category": "dependency"},
    {"tool": "bandit", "severity": "high", "rule": "B608", "message": "SQL built from text", "file": "app/db.py", "line": 4, "category": "code", "cwe": "CWE-89"},
    {"tool": "gitleaks", "severity": "high", "rule": "generic-api-key", "message": "secret", "file": "conf.py", "line": 1, "category": "secret"},
]
TOOLS = [{"name": "osv-scanner", "status": "ok", "findings": 1}, {"name": "bandit", "status": "ok", "findings": 1},
         {"name": "gitleaks", "status": "ok", "findings": 1}, {"name": "semgrep", "status": "error", "detail": "network down", "findings": 0}]  # fmt: skip


def test_full_report(tmp_path, capsys):
    report = write(tmp_path, "scan.json", F, TOOLS)
    before = write(tmp_path, "before.json", F + [{"tool": "bandit", "severity": "high", "rule": "B301", "message": "pickle", "file": "a.py", "line": 1, "category": "code"}], TOOLS)
    decisions = tmp_path / "d.json"
    decisions.write_text(json.dumps({"version": 1, "decisions": [
        {"tool": "gitleaks", "file": "*", "decision": "false-positive", "owner": "Ann", "justification": "fake key"},
        {"rule": "B608", "decision": "mitigate", "owner": "Bob", "due": "2099-01-01"}]}))  # fmt: skip
    out = tmp_path / "r.html"
    code = cli.main(["report", report, "--html", str(out), "--title", "Assessment <ACME>", "--target", "shop v1", "--tester", "Ergi",
                     "--authorized-by", "Prof. X (email 2026-11-01)", "--scope", "source code", "--decisions", str(decisions),
                     "--kev-file", str(FIX / "kev.json"), "--epss-file", str(FIX / "epss.json"), "--retest", before])  # fmt: skip
    assert code == 3  # semgrep failed: the assessment is incomplete, and the exit code says so
    html = out.read_text()
    for section in ("1. Scope and authorization", "2. Executive summary", "3. Method and coverage", "4. Risk matrix and register",
                    "5. Risk treatment", "6. Threats", "7. Retest", "8. Appendix"):  # fmt: skip
        assert section in html, section
    assert "<script>x" not in html and "Assessment &lt;ACME&gt;" in html and "Content-Security-Policy" in html
    assert "KEV" in html and "T1190" in html and "Incomplete" in html and "network down" in html
    assert "fake key" in html and "Prof. X" in html and "No authorization is recorded" not in html
    assert "Fixed" in html


def test_missing_authorization_is_flagged(tmp_path, capsys):
    report = write(tmp_path, "scan.json", F, TOOLS[:3])
    out = tmp_path / "r.html"
    assert cli.main(["report", report, "--html", str(out)]) == 0
    html = out.read_text()
    assert "No authorization is recorded" in html and "5. Risk treatment" not in html and "7. Retest" not in html


def test_bad_input(tmp_path, capsys):
    assert cli.main(["report", str(tmp_path / "missing.json"), "--html", str(tmp_path / "r.html")]) == 2
