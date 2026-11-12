"""History over several scans: ordering, deltas, incomplete scans."""

import json
import os

from polyscan import cli, history
from polyscan.risk import load_report


def write(tmp_path, name, rules, generated=None, tools=None):
    findings = [{"tool": "bandit", "severity": sev, "rule": rule, "message": "<i>m</i>", "file": "a.py", "line": 1} for rule, sev in rules]
    data = {"polyscan": "x", "root": ".", "tools": tools or [{"name": "bandit", "status": "ok"}], "findings": findings}
    if generated:
        data["generated"] = generated
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def test_order_and_deltas(tmp_path):
    third = write(tmp_path, "c.json", [("B1", "high")], "2026-11-12T10:00:00Z")
    first = write(tmp_path, "a.json", [("B1", "high"), ("B2", "critical")], "2026-11-01T10:00:00Z")
    second = write(tmp_path, "b.json", [("B1", "high"), ("B2", "critical"), ("B3", "low")], "2026-11-05T10:00:00Z")
    pts = history.build([load_report(p) for p in (third, first, second)])
    assert [p.source.path for p in pts] == [first, second, third]
    assert (pts[0].new, pts[0].fixed) == (None, None)
    assert (pts[1].new, pts[1].fixed) == (1, 0) and (pts[2].new, pts[2].fixed) == (0, 2)
    assert pts[2].counts == {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}


def test_incomplete_scan_is_marked_and_fixes_are_not_verified(tmp_path):
    a = write(tmp_path, "a.json", [("B1", "high")], "2026-11-01T10:00:00Z")
    b = write(tmp_path, "b.json", [], "2026-11-02T10:00:00Z", [{"name": "bandit", "status": "error", "detail": "crash"}])
    pts = history.build([load_report(a), load_report(b)])
    assert pts[1].gaps == 1 and pts[1].fixed == 0 and pts[1].not_verified == 1
    assert "INCOMPLETE" in history.to_terminal(pts) and "incomplete" in history.to_html(pts)
    assert cli.main(["history", a, b]) == 3


def test_reports_without_a_time_use_the_file_time_and_say_so(tmp_path):
    old = write(tmp_path, "old.json", [("B1", "low")])
    os.utime(old, (1_000_000_000, 1_000_000_000))
    new = write(tmp_path, "new.json", [], "2026-11-01T10:00:00Z")
    bad = write(tmp_path, "bad.json", [], "<script>")
    pts = history.build([load_report(new), load_report(old)])
    assert pts[0].from_file_time and pts[0].when.startswith("2001-09-09") and "*" in history.to_terminal(pts)
    assert load_report(bad).generated == ""  # a malformed time is not trusted


def test_outputs(tmp_path, capsys):
    a = write(tmp_path, "a.json", [("B1", "high")], "2026-11-01T10:00:00Z")
    b = write(tmp_path, "b.json", [("B1", "high"), ("B2", "medium")], "2026-11-02T10:00:00Z")
    out = tmp_path / "h.html"
    assert cli.main(["history", b, a, "--html", str(out), "--json", str(tmp_path / "h.json"), "--markdown", str(tmp_path / "h.md")]) == 0
    html = out.read_text()
    assert "<svg" in html and "<script" not in html and "Content-Security-Policy" in html
    data = json.loads((tmp_path / "h.json").read_text())
    assert data["kind"] == "history" and [s["findings"] for s in data["scans"]] == [1, 2] and data["scans"][1]["new"] == 1
    assert "+1 new" in (tmp_path / "h.md").read_text()
    assert cli.main(["history", str(tmp_path / "missing.json")]) == 2


def test_new_reports_carry_the_time():
    from polyscan.report import to_json
    from polyscan.scanner import ScanResult

    assert json.loads(to_json(ScanResult(".", {})))["generated"].endswith("Z")
