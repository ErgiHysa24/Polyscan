import io
import json

from polyscan.models import ERROR, OK, Finding, Severity, ToolResult
from polyscan.report import to_html, to_json, to_terminal
from polyscan.scanner import ScanResult

EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


def make(findings=(), status=OK, root="/p"):
    return ScanResult(root, {"python": 1}, [ToolResult("fake", status, "via local", list(findings))])


def f(**kw):
    base = dict(tool="t", severity=Severity.HIGH, rule="r", message="m", file="a.py", line=3)
    base.update(kw)
    return Finding(**base)


def test_html_escapes_everything_that_comes_from_scanned_code():
    res = make(
        [f(message=EVIL, rule=EVIL, file=EVIL, snippet=EVIL, tool=EVIL)],
        root=EVIL,
    )
    page = to_html(res)
    assert "<script>" not in page and "<img" not in page
    assert "&lt;script&gt;" in page


def test_html_blocks_scripts_with_a_content_security_policy():
    page = to_html(make())
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "<script" not in page  # the report itself needs no JavaScript


def test_html_warns_when_a_check_did_not_run():
    assert "did not run" in to_html(make(status=ERROR))
    assert "did not run" not in to_html(make(status=OK))


def test_terminal_strips_escape_sequences_from_scanned_code():
    res = make([f(message="\x1b[2J\x1b[31mgotcha", file="a\x1b]0;pwn\x07.py")])
    out = to_terminal(res, stream=io.StringIO())
    assert "\x1b" not in out and "\x07" not in out


def test_terminal_has_no_color_when_not_a_tty():
    out = to_terminal(make([f()]), stream=io.StringIO())
    assert "\x1b[" not in out


def test_terminal_warns_when_a_check_did_not_run():
    assert "did NOT run" not in to_terminal(make(status=OK), stream=io.StringIO())
    assert "did not run" in to_terminal(make(status=ERROR), stream=io.StringIO())


def test_terminal_limit_mentions_the_rest():
    res = make([f(line=i) for i in range(1, 6)])
    assert "and 3 more" in to_terminal(res, limit=2, stream=io.StringIO())


def test_findings_are_sorted_most_severe_first():
    res = make([f(severity=Severity.LOW), f(severity=Severity.CRITICAL), f(severity=Severity.MEDIUM)])
    assert [x.severity for x in res.findings] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_json_report_is_valid_and_counts_severities():
    data = json.loads(to_json(make([f(), f(severity=Severity.LOW)])))
    assert data["summary"]["high"] == 1 and data["summary"]["low"] == 1
    assert data["tools"][0]["status"] == "ok"
    assert len(data["findings"]) == 2


def test_markdown_summary_neutralizes_scanned_text():
    from polyscan.report import to_markdown

    evil = "[click](javascript:alert(1)) <img src=x> | `x` **bold**"
    md = to_markdown(make([f(rule=evil, file=evil)]))
    assert "<img" not in md and "](javascript" not in md
    # a "|" from scanned text must not open an extra table column
    row = next(line for line in md.splitlines() if line.startswith("| high"))
    assert row.replace("\\|", "").count("|") == 4


def test_markdown_warns_about_gaps():
    from polyscan.report import to_markdown

    assert "did not run" in to_markdown(make(status=ERROR))
