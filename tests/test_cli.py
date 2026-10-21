import json

import pytest

from polyscan import cli
from polyscan.models import ERROR, OK, UNAVAILABLE, Finding, Severity, ToolResult
from polyscan.scanner import ScanResult


def fake_scan(findings=(), status=OK):
    def _scan(root, mode, opts, only, timeout):
        return ScanResult(str(root), {"python": 1}, [ToolResult("fake", status, "", list(findings))])

    return _scan


def finding(sev):
    return Finding("t", sev, "r", "m", file="a.py", line=1)


def run(monkeypatch, tmp_path, scan_fn, *args):
    monkeypatch.setattr(cli, "scan", scan_fn)
    return cli.main(["scan", str(tmp_path), *args])


def test_exit_0_when_clean(monkeypatch, tmp_path):
    assert run(monkeypatch, tmp_path, fake_scan()) == 0


def test_exit_1_when_finding_reaches_threshold(monkeypatch, tmp_path):
    assert run(monkeypatch, tmp_path, fake_scan([finding(Severity.HIGH)])) == 1


def test_low_findings_do_not_fail_by_default(monkeypatch, tmp_path):
    assert run(monkeypatch, tmp_path, fake_scan([finding(Severity.LOW)])) == 0


def test_fail_on_can_be_lowered_or_disabled(monkeypatch, tmp_path):
    scan = fake_scan([finding(Severity.LOW)])
    assert run(monkeypatch, tmp_path, scan, "--fail-on", "low") == 1
    scan = fake_scan([finding(Severity.CRITICAL)])
    assert run(monkeypatch, tmp_path, scan, "--fail-on", "none") == 0


def test_exit_3_when_a_tool_failed(monkeypatch, tmp_path):
    assert run(monkeypatch, tmp_path, fake_scan(status=ERROR)) == 3


def test_missing_tool_only_fails_with_strict(monkeypatch, tmp_path):
    assert run(monkeypatch, tmp_path, fake_scan(status=UNAVAILABLE)) == 0
    assert run(monkeypatch, tmp_path, fake_scan(status=UNAVAILABLE), "--strict") == 3


def test_findings_win_over_tool_errors(monkeypatch, tmp_path):
    assert run(monkeypatch, tmp_path, fake_scan([finding(Severity.HIGH)], ERROR)) == 1


def test_exit_2_for_a_bad_path(capsys):
    assert cli.main(["scan", "/definitely/not/here"]) == 2


def test_exit_2_for_unknown_tool(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path), "--only", "nope"]) == 2
    assert "unknown tool" in capsys.readouterr().err


def test_writes_reports(monkeypatch, tmp_path):
    out_html, out_json = tmp_path / "r.html", tmp_path / "r.json"
    run(monkeypatch, tmp_path, fake_scan([finding(Severity.LOW)]), "--html", str(out_html), "--json", str(out_json))
    assert "<html" in out_html.read_text(encoding="utf-8")
    assert json.loads(out_json.read_text(encoding="utf-8"))["summary"]["low"] == 1


def test_bad_fail_on_value_is_rejected(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["scan", str(tmp_path), "--fail-on", "bananas"])


def test_doctor_runs(capsys):
    assert cli.main(["doctor"]) == 0
    assert "semgrep" in capsys.readouterr().out
