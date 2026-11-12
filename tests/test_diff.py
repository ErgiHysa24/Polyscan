"""Retest: comparing two reports. The key rule: a finding that vanished because its tool did not run is NOT fixed."""

import json

import pytest

from polyscan import cli, diff
from polyscan.models import Finding, Severity
from polyscan.risk import load_report


def fnd(rule="B608", file="app/db.py", line=3, tool="bandit", severity=Severity.HIGH):
    return Finding(tool, severity, rule, f"{rule} msg <b>x</b>", file, line, "code")


def report(tmp_path, name, findings, tools=None):
    p = tmp_path / name
    tools = tools if tools is not None else [{"name": t, "status": "ok"} for t in sorted({f.tool for f in findings} | {"bandit", "semgrep"})]
    p.write_text(json.dumps({"polyscan": "x", "root": ".", "kind": "folder", "tools": tools, "findings": [f.to_dict() for f in findings]}))
    return str(p)


def compare(tmp_path, before, after, tools_after=None):
    return diff.compare(load_report(report(tmp_path, "a.json", before)), load_report(report(tmp_path, "b.json", after, tools_after)))


def test_the_four_groups(tmp_path):
    d = compare(tmp_path, [fnd(), fnd(rule="B105")], [fnd(line=10), fnd(rule="B301", severity=Severity.CRITICAL)])
    assert d.counts() == {"fixed": 1, "not_verified": 0, "still_open": 1, "new": 1}
    assert d.groups["fixed"][0].rule == "B105" and d.groups["new"][0].rule == "B301"
    assert d.groups["still_open"][0].line == 10  # matched although the line moved


def test_counts_within_one_file(tmp_path):
    d = compare(tmp_path, [fnd(line=1), fnd(line=2), fnd(line=3)], [fnd(line=7)])
    assert d.counts()["fixed"] == 2 and d.counts()["still_open"] == 1


def test_a_tool_that_did_not_run_the_second_time_proves_nothing(tmp_path):
    tools = [{"name": "bandit", "status": "error", "detail": "crashed"}, {"name": "semgrep", "status": "ok"}]
    d = compare(tmp_path, [fnd(), fnd(tool="semgrep", rule="s1")], [], tools)
    assert d.counts() == {"fixed": 1, "not_verified": 1, "still_open": 0, "new": 0}
    assert d.groups["not_verified"][0].tool == "bandit" and d.groups["fixed"][0].tool == "semgrep"
    assert d.after_gaps()


def test_gitleaks_history_counts_as_gitleaks(tmp_path):
    tools = [{"name": "gitleaks-history", "status": "ok"}]
    d = compare(tmp_path, [fnd(tool="gitleaks", rule="aws")], [], tools)
    assert d.counts()["fixed"] == 1


def test_outputs_escape_untrusted_text(tmp_path):
    d = compare(tmp_path, [fnd()], [fnd(rule="B301")])
    html = diff.to_html(d)
    assert "<b>x</b>" not in html and "&lt;b&gt;x" in html and "Content-Security-Policy" in html
    md = diff.to_markdown(d)
    assert "### New (1)" in md and "<b>" not in md
    data = json.loads(diff.to_json(d))
    assert data["kind"] == "retest" and data["summary"]["new"] == 1
    assert "\x1b" not in diff.to_terminal(compare(tmp_path, [fnd(rule="\x1b[31mred")], []))


def test_cli_exit_codes(tmp_path, capsys):
    a = report(tmp_path, "a.json", [fnd()])
    b = report(tmp_path, "b.json", [fnd(rule="B301", severity=Severity.CRITICAL)])
    assert cli.main(["diff", a, b]) == 0
    assert cli.main(["diff", a, b, "--fail-on", "high"]) == 1
    c = report(tmp_path, "c.json", [], [{"name": "bandit", "status": "unavailable"}])
    assert cli.main(["diff", a, c]) == 3  # incomplete retest: never "all fixed"
    out = tmp_path / "r.html"
    assert cli.main(["diff", a, b, "--html", str(out), "--json", str(tmp_path / "r.json"), "--markdown", str(tmp_path / "r.md")]) == 0
    assert out.exists() and (tmp_path / "r.md").exists()
    assert cli.main(["diff", a, str(tmp_path / "missing.json")]) == 2
