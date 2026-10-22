"""Risk assessment: the scoring rules, reading reports, the output formats, the exit codes."""

import json

import pytest

from polyscan import cli, riskreport
from polyscan.models import Finding, Severity
from polyscan.risk import (
    Context, assess, level_for, load_report, merge, mitigation_for, score_group,
)  # fmt: skip

S = Severity


def f(category="code", severity=S.HIGH, rule="r1", message="msg", file="a.py", line=1, tool="semgrep"):
    return Finding(tool=tool, severity=severity, rule=rule, message=message, file=file, line=line, category=category)


# ----------------------------------------------------------------- scoring


@pytest.mark.parametrize("score,level", [(1, "low"), (5, "low"), (6, "medium"), (12, "medium"), (13, "high"), (19, "high"), (20, "critical"), (25, "critical")])
def test_levels(score, level):
    assert level_for(score) == level


@pytest.mark.parametrize("kind,severity,exposure,data,likelihood,impact", [
    ("secret", S.HIGH, "internet", "personal", 5, 5),   # 4+1, 4+1
    ("code", S.HIGH, "internet", "personal", 4, 5),
    ("code", S.HIGH, "internal", "internal", 3, 4),
    ("code", S.HIGH, "local", "public", 2, 3),
    ("runtime", S.MEDIUM, "internet", "personal", 4, 3),  # personal data does NOT raise a medium
    ("runtime", S.LOW, "internet", "public", 4, 1),       # public data lowers everything
    ("config", S.MEDIUM, "internet", "personal", 3, 3),
    ("dependency", S.CRITICAL, "internet", "personal", 4, 5),  # impact never above 5
    ("config", S.INFO, "local", "public", 1, 1),               # never below 1
])  # fmt: skip
def test_scores(kind, severity, exposure, data, likelihood, impact):
    got_l, got_i, reasons = score_group(kind, severity, Context(exposure, data))
    assert (got_l, got_i) == (likelihood, impact)
    assert any(r.startswith("Likelihood") for r in reasons) and any(r.startswith("Impact") for r in reasons)


def test_every_score_comes_with_its_reasons():
    (risk,) = assess([f("secret")], Context("internet", "personal"))
    text = " ".join(risk.reasons)
    assert "internet" in text and "personal" in text and "secret" in text


def test_a_bad_context_is_refused():
    with pytest.raises(ValueError):
        Context("moon", "public")
    with pytest.raises(ValueError):
        Context("internet", "secret-stuff")


def test_a_kind_nobody_planned_for_still_gets_a_score():
    (risk,) = assess([f("something-new")], Context())
    assert 1 <= risk.score <= 25


# ----------------------------------------------------------------- the register


def test_same_rule_in_many_places_is_one_risk_with_all_places():
    findings = [f(file=f"f{i}.py", line=i) for i in range(1, 8)]
    (risk,) = assess(findings, Context())
    assert risk.count == 7 and len(risk.where) == 6 and risk.where[-1] == "... and 2 more"


def test_sorted_by_score_and_numbered():
    risks = assess([f("config", S.LOW, "a"), f("secret", S.HIGH, "b"), f("code", S.MEDIUM, "c")], Context())
    assert [r.id for r in risks] == ["R-001", "R-002", "R-003"]
    assert [r.rule for r in risks] == ["b", "c", "a"]
    assert [r.score for r in risks] == sorted((r.score for r in risks), reverse=True)


def test_a_group_takes_its_worst_severity():
    (risk,) = assess([f(severity=S.LOW, line=1), f(severity=S.CRITICAL, line=2)], Context())
    assert risk.severity == S.CRITICAL


def test_nothing_found_is_an_empty_register():
    assert assess([], Context()) == []


# ----------------------------------------------------------------- mitigations


@pytest.mark.parametrize("kind,rule,message,expect", [
    ("code", "x", "SQL built from user input", "parameterized"),
    ("code", "xss", "innerHTML with user data", "Escape output"),
    ("runtime", "10038", "Content Security Policy (CSP) Header Not Set", "Content-Security-Policy"),
    ("runtime", "10010", "Cookie No HttpOnly Flag", "HttpOnly"),
    ("code", "B605", "Starting a process with a shell, possible injection", "argument list"),
    ("secret", "aws", "AWS key", "revoke"),
    ("dependency", "GHSA-1", "lodash: bad. Fix: update lodash to 4.18.1.", "Fix: update lodash to 4.18.1."),
    ("dependency", "RUSTSEC-1", "time 0.1.43: segfault. Fixed in: >=0.2.23.", "Fixed in: >=0.2.23."),
    ("dependency", "x", "no hint here", "patched version"),
    ("code", "zzz", "unknown", "Review the code"),
])  # fmt: skip
def test_mitigation(kind, rule, message, expect):
    assert expect.lower() in mitigation_for(kind, rule, message).lower()


# ----------------------------------------------------------------- reading reports


def write(tmp_path, data, name="r.json"):
    p = tmp_path / name
    p.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return str(p)


def report(findings=(), tools=(), notes=(), kind="folder"):
    return {"polyscan": "0.3.0", "root": "/p", "kind": kind, "notes": list(notes), "tools": list(tools),
            "findings": [x.to_dict() for x in findings]}  # fmt: skip


def test_load_a_real_report(tmp_path):
    src = load_report(write(tmp_path, report([f(), f("secret", S.CRITICAL, "k", file=".env")])))
    assert [x.rule for x in src.findings] == ["r1", "k"] and src.findings[1].severity == S.CRITICAL


@pytest.mark.parametrize("content", ["", "not json", "[]", "{}", '{"polyscan": "1", "findings": "x"}',
    '{"polyscan": "1", "findings": [{"tool": "t"}]}',
    '{"polyscan": "1", "findings": [{"tool": "t", "severity": "banana"}]}',
    '{"polyscan": "1", "findings": [5]}'])  # fmt: skip
def test_things_that_are_not_reports_are_refused(tmp_path, content):
    with pytest.raises(ValueError):
        load_report(write(tmp_path, content))


def test_missing_file_and_huge_file_are_refused(tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        load_report(str(tmp_path / "nope.json"))
    from polyscan import risk

    monkeypatch.setattr(risk, "MAX_REPORT_BYTES", 10)
    with pytest.raises(ValueError, match="too large"):
        load_report(write(tmp_path, report([f()])))


def test_two_overlapping_reports_do_not_double_count(tmp_path):
    a = load_report(write(tmp_path, report([f(), f(rule="r2")]), "a.json"))
    b = load_report(write(tmp_path, report([f(), f(rule="r3")]), "b.json"))
    assert sorted(x.rule for x in merge([a, b])) == ["r1", "r2", "r3"]


# ----------------------------------------------------------------- gaps must show everywhere

GAP_TOOLS = [{"name": "zap", "status": "error", "detail": "no report"}, {"name": "osv-scanner", "status": "ok", "detail": "", "findings": 1},
             {"name": "npm-audit", "status": "unavailable", "detail": "npm is not installed"}]  # fmt: skip


def sources_with_gaps(tmp_path):
    return [load_report(write(tmp_path, report([f()], GAP_TOOLS, ["a note"])))]


def test_gaps_and_notes_are_in_every_format(tmp_path):
    srcs = sources_with_gaps(tmp_path)
    risks = assess(merge(srcs), Context())
    for text in (riskreport.to_terminal(Context(), risks, srcs), riskreport.to_markdown(Context(), risks, srcs),
                 riskreport.to_html(Context(), risks, srcs), riskreport.to_json(Context(), risks, srcs)):  # fmt: skip
        text = text.replace("\\", "")  # Markdown escapes characters such as "-" with a backslash
        assert "zap: error" in text and "npm-audit: unavailable" in text and "a note" in text
        assert "osv-scanner: ok" not in text  # a tool that worked is not a gap


def test_an_empty_register_with_gaps_does_not_look_clean(tmp_path):
    srcs = [load_report(write(tmp_path, report([], GAP_TOOLS)))]
    out = riskreport.to_terminal(Context(), [], srcs)
    assert "did not run" in out and "see the warning" in out


# ----------------------------------------------------------------- untrusted text


EVIL = '<script>alert(1)</script> \x1b[31mred\x1b[0m | [x](http://evil) `code`'


def test_text_from_a_report_cannot_inject_html_ansi_or_markdown(tmp_path):
    srcs = [load_report(write(tmp_path, report([f(message=EVIL, rule="<b>r</b>", file="<img src=x onerror=1>")])))]
    ctx = Context()
    risks = assess(merge(srcs), ctx)
    html = riskreport.to_html(ctx, risks, srcs)
    assert "<script>alert" not in html and "<img src=x" not in html and "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html
    assert "\x1b" not in riskreport.to_terminal(ctx, risks, srcs)
    md = riskreport.to_markdown(ctx, risks, srcs)
    assert "[x](http" not in md and "<script>" not in md


def test_json_output_is_valid_and_complete(tmp_path):
    srcs = sources_with_gaps(tmp_path)
    data = json.loads(riskreport.to_json(Context("internal", "public"), assess(merge(srcs), Context("internal", "public")), srcs))
    assert data["context"] == {"exposure": "internal", "data": "public"} and data["kind"] == "risk-assessment"
    assert data["risks"][0]["id"] == "R-001" and data["risks"][0]["reasons"] and data["coverage_gaps"]
    assert sum(data["summary"].values()) == len(data["risks"])


# ----------------------------------------------------------------- the command


def run(tmp_path, capsys, data, *extra):
    path = write(tmp_path, data)
    code = cli.main(["risk", path, *extra])
    return code, capsys.readouterr()


def test_cli_ok_and_files_written(tmp_path, capsys):
    out_html, out_json, out_md = (tmp_path / n for n in ("r.html", "r.json", "r.md"))
    code, cap = run(tmp_path, capsys, report([f("secret")]), "--html", str(out_html), "--json", str(out_json), "--markdown", str(out_md))
    assert code == 0 and "R-001" in cap.out and out_html.exists() and json.loads(out_json.read_text())["risks"] and out_md.exists()


def test_cli_fail_on_level(tmp_path, capsys):
    data = report([f("code", S.MEDIUM)])  # L4 x I3 = 12: medium
    assert run(tmp_path, capsys, data, "--fail-on", "medium")[0] == 1
    assert run(tmp_path, capsys, data, "--fail-on", "high")[0] == 0
    assert run(tmp_path, capsys, data)[0] == 0


def test_cli_context_changes_the_result(tmp_path, capsys):
    data = report([f("code", S.HIGH)])
    assert run(tmp_path, capsys, data, "--fail-on", "critical")[0] == 1  # internet + personal: 20
    assert run(tmp_path, capsys, data, "--fail-on", "critical", "--exposure", "local", "--data", "public")[0] == 0


def test_cli_a_failed_check_in_the_source_is_exit_3(tmp_path, capsys):
    assert run(tmp_path, capsys, report([], GAP_TOOLS))[0] == 3
    only_missing = [GAP_TOOLS[2]]
    assert run(tmp_path, capsys, report([], only_missing))[0] == 0
    assert run(tmp_path, capsys, report([], only_missing), "--strict")[0] == 3


def test_cli_bad_input_is_exit_2_with_a_message(tmp_path, capsys):
    code, cap = run(tmp_path, capsys, "not a report")
    assert code == 2 and "error:" in cap.err
    assert cli.main(["risk", str(tmp_path / "missing.json")]) == 2
