"""Risk treatment decisions: validation, matching, effect on the register, reports and exit codes."""

import json
from datetime import date

import pytest

from polyscan import cli, riskreport
from polyscan.models import Finding, Severity
from polyscan.risk import Context, assess
from polyscan.treatment import load, parse, template

TODAY = date(2026, 11, 12)


def fnd(rule="B608", file="app/db.py", tool="bandit", severity=Severity.HIGH, line=3, category="code"):
    return Finding(tool=tool, severity=severity, rule=rule, message=f"{rule} problem", file=file, line=line, category=category)


def plan(*decisions):
    return parse({"version": 1, "decisions": list(decisions)}, "d.json", TODAY)


ACCEPT = {"rule": "B608", "decision": "accept", "owner": "Mario", "justification": "internal only", "expires": "2026-12-31"}


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("entry, message", [
    ({"decision": "accept", "owner": "M", "justification": "j", "expires": "2026-12-31"}, "at least a rule or a file"),
    ({"rule": "x", "decision": "ignore", "owner": "M"}, "decision must be one of"),
    ({"rule": "x", "decision": "accept", "justification": "j", "expires": "2026-12-31"}, "needs an owner"),
    ({"rule": "x", "decision": "accept", "owner": "M", "expires": "2026-12-31"}, "needs a justification"),
    ({"rule": "x", "decision": "accept", "owner": "M", "justification": "j"}, "expiry date"),
    ({"rule": "x", "decision": "mitigate", "owner": "M"}, "due date"),
    ({"rule": "x", "decision": "false-positive", "owner": "M"}, "needs a justification"),
    ({"rule": "x", "decision": "accept", "owner": "M", "justification": "j", "expires": "31/12/2026"}, "YYYY-MM-DD"),
    ({"rule": "x", "decision": "mitigate", "owner": "M", "due": "2026-12-01", "status": "almost"}, "status must be"),
    ({"rule": "x", "decision": "mitigate", "owner": "M", "due": "2026-12-01", "severity": "low"}, "unknown field"),
    ({"rule": 5, "decision": "todo"}, "must be text"),
    ({"rule": "x" * 600, "decision": "todo"}, "longer than"),
])  # fmt: skip
def test_bad_entries_are_refused_with_a_clear_message(entry, message):
    with pytest.raises(ValueError, match=message):
        plan(entry)


def test_the_file_shape_is_checked(tmp_path):
    for bad in ('{"decisions": []}', '[]', '{"version": 2, "decisions": []}'):
        with pytest.raises(ValueError, match="version"):
            parse(json.loads(bad))
    p = tmp_path / "d.json"
    p.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load(str(p))
    with pytest.raises(ValueError, match="cannot read"):
        load(str(tmp_path / "missing.json"))


def test_todo_entries_need_nothing_else():
    assert plan({"rule": "x", "decision": "todo"}).warnings() == ["1 decision(s) still marked 'todo' in d.json"]


# ------------------------------------------------------------------ matching and effects
def test_accepted_risk_stays_but_no_longer_counts():
    (r,) = assess([fnd()], Context(), plan(ACCEPT))
    assert r.state == "accepted" and not r.active and r.treatment.owner == "Mario"


def test_expired_acceptance_counts_again_with_a_warning():
    p = plan({**ACCEPT, "expires": "2026-11-01"})
    (r,) = assess([fnd()], Context(), p)
    assert r.state == "acceptance-expired" and r.active
    assert any("expired on 2026-11-01" in w for w in p.warnings())


def test_false_positives_leave_the_register_but_are_listed():
    p = plan({"rule": "B608", "file": "app/reports/*", "decision": "false-positive", "owner": "Mario", "justification": "constant query"})
    risks = assess([fnd(file="app/reports/a.py"), fnd(file="app/db.py")], Context(), p)
    assert [r.where for r in risks] == [["app/db.py:3"]]  # only the real one is left
    assert [(f.file, d.owner) for f, d in p.false_positives] == [("app/reports/a.py", "Mario")]


def test_a_risk_with_different_decisions_is_split():
    p = plan({**ACCEPT, "file": "tests/*"})
    risks = assess([fnd(file="tests/t.py"), fnd(file="app/db.py")], Context(), p)
    assert sorted(r.state for r in risks) == ["accepted", "untreated"]


def test_first_matching_decision_wins_and_patterns_work():
    p = plan({**ACCEPT, "rule": "B6*"}, {"rule": "B608", "decision": "mitigate", "owner": "Team", "due": "2026-12-01"})
    (r,) = assess([fnd()], Context(), p)
    assert r.treatment.index == 1
    assert any("#2" in w and "matches no finding" in w for w in p.warnings())


def test_mitigation_states():
    p = plan({"rule": "B608", "decision": "mitigate", "owner": "Team", "due": "2026-11-01"})
    (r,) = assess([fnd()], Context(), p)
    assert r.state == "overdue" and r.active and any("was due on 2026-11-01" in w for w in p.warnings())
    p = plan({"rule": "B608", "decision": "mitigate", "owner": "Team", "due": "2027-01-01"})
    assert assess([fnd()], Context(), p)[0].state == "planned"


def test_done_but_still_found_is_not_treated():
    p = plan({"rule": "B608", "decision": "mitigate", "owner": "Team", "due": "2026-12-01", "status": "done"})
    (r,) = assess([fnd()], Context(), p)
    assert r.active and any("still finds it" in w for w in p.warnings())


def test_no_plan_means_untreated():
    (r,) = assess([fnd()], Context())
    assert r.state == "untreated" and r.active and r.treatment is None


def test_template_has_one_todo_per_risk_and_loads_back(tmp_path):
    risks = assess([fnd(), fnd(rule="B105", category="secret")], Context())
    text = template(risks)
    p = tmp_path / "t.json"
    p.write_text(text)
    loaded = load(str(p), TODAY)
    assert [d.decision for d in loaded.decisions] == ["todo", "todo"]
    assert {d.rule for d in loaded.decisions} == {"B608", "B105"}


# ------------------------------------------------------------------ reports
def test_reports_show_decisions_and_false_positives():
    p = plan(ACCEPT, {"rule": "B105", "decision": "false-positive", "owner": "Ann", "justification": "<b>test data</b>"})
    risks = assess([fnd(), fnd(rule="B105")], Context(), p)
    data = json.loads(riskreport.to_json(Context(), risks, [], p))
    assert data["treatment"]["states"] == {"accepted": 1} and data["treatment"]["active"] == 0
    assert data["treatment"]["false_positives"][0]["decided_by"] == "Ann"
    assert data["risks"][0]["treatment"]["expires"] == "2026-12-31"
    assert "accepted" in riskreport.to_terminal(Context(), risks, [], plan=p)
    assert "Mario" in riskreport.to_markdown(Context(), risks, [], p)
    html = riskreport.to_html(Context(), risks, [], p)
    assert "Risk treatment" in html and "<b>test data</b>" not in html and "&lt;b&gt;test data" in html


# ------------------------------------------------------------------ CLI
def write_report(tmp_path, findings):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps({"polyscan": "x", "root": ".", "kind": "folder", "tools": [], "findings": [f.to_dict() for f in findings]}))
    return str(p)


def test_cli_accepted_risk_does_not_fail_the_build(tmp_path, capsys):
    report = write_report(tmp_path, [fnd(severity=Severity.CRITICAL)])
    assert cli.main(["risk", report, "--fail-on", "high"]) == 1
    d = tmp_path / "d.json"
    d.write_text(json.dumps({"version": 1, "decisions": [{**ACCEPT, "expires": "2099-01-01"}]}))
    assert cli.main(["risk", report, "--fail-on", "high", "--decisions", str(d)]) == 0
    d.write_text(json.dumps({"version": 1, "decisions": [{**ACCEPT, "expires": "2000-01-01"}]}))
    assert cli.main(["risk", report, "--fail-on", "high", "--decisions", str(d)]) == 1  # expired: counts again


def test_cli_bad_decisions_file_is_a_usage_error(tmp_path, capsys):
    report = write_report(tmp_path, [fnd()])
    d = tmp_path / "d.json"
    d.write_text(json.dumps({"version": 1, "decisions": [{"rule": "x", "decision": "accept"}]}))
    assert cli.main(["risk", report, "--decisions", str(d)]) == 2
    assert "needs an owner" in capsys.readouterr().err


def test_cli_writes_a_template(tmp_path, capsys):
    report = write_report(tmp_path, [fnd(), fnd(rule="B105")])
    out = tmp_path / "todo.json"
    assert cli.main(["risk", report, "--decisions-template", str(out)]) == 0
    assert len(json.loads(out.read_text())["decisions"]) == 2
