"""npm audit / cargo audit: the parsers (real output) and the runner that loops over lockfiles."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from polyscan import auditrun
from polyscan.models import ERROR, OK, SKIPPED, Severity
from polyscan.scanner import run_tool
from polyscan.tools import NpmAudit, ScanOptions, parse_npm_audit

FIX = Path(__file__).parent / "fixtures"
NPM = (FIX / "npm-audit.json").read_text(encoding="utf-8")


# ----------------------------------------------------------------- npm parser (real output)


def test_npm_real_output():
    findings = parse_npm_audit(NPM, "/proj")
    assert len(findings) == 20
    assert all(f.tool == "npm-audit" and f.category == "dependency" and f.line == 0 for f in findings)
    assert {f.file for f in findings} == {"javascript/package-lock.json"}
    by_rule = {f.rule: f for f in findings}
    assert by_rule["GHSA-qwcr-r2fm-qrc7"].severity == Severity.HIGH
    assert by_rule["GHSA-pxg6-pf52-xh8x"].severity == Severity.LOW
    assert "Fix: update express to 4.22.3" in by_rule["GHSA-qwcr-r2fm-qrc7"].message


def test_an_advisory_that_makes_several_packages_vulnerable_counts_once():
    # npm lists "body-parser" as a plain string under express; only the dict is a finding.
    data = json.loads(NPM)
    report = data["audits"][0]["report"]["vulnerabilities"]
    strings = [v for p in report.values() for v in p["via"] if isinstance(v, str)]
    assert strings, "the fixture should contain a package that is affected only through another one"
    rules = [f.rule for f in parse_npm_audit(NPM, "/proj")]
    assert len(rules) == len(set(rules))


def test_npm_clean_project_is_no_findings():
    clean = {"kind": "npm", "audits": [{"dir": ".", "lockfile": "package-lock.json", "report": {"vulnerabilities": {}}}]}
    assert parse_npm_audit(json.dumps(clean), "/p") == []


def test_npm_lockfile_in_the_root_has_a_plain_path():
    data = {"kind": "npm", "audits": [{"dir": ".", "lockfile": "package-lock.json", "report": {"vulnerabilities": {
        "x": {"fixAvailable": False, "via": [{"source": 5, "name": "x", "title": "bad", "severity": "critical", "range": "<2"}]}}}}]}  # fmt: skip
    (f,) = parse_npm_audit(json.dumps(data), "/p")
    assert f.file == "package-lock.json" and f.severity == Severity.CRITICAL and f.rule == "5"
    assert "No fix published yet" in f.message


def test_something_that_is_not_our_output_is_an_error_not_clean():
    for bad in ("", "{}", '{"error": {"code": "ENOLOCK"}}', "[]"):
        with pytest.raises((ValueError, TypeError)):
            parse_npm_audit(bad, "/p")


# ----------------------------------------------------------------- runner


class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def test_finds_every_lockfile_but_not_node_modules(tmp_path):
    for d in (".", "api", "web", "web/node_modules/pkg", "target/debug", "skip"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d / "package-lock.json").write_text("{}")
    found = auditrun.find_lock_dirs(tmp_path, "package-lock.json", ("skip",))
    assert [p.relative_to(tmp_path).as_posix() for p in found] == [".", "api", "web"]


def test_npm_exit_1_with_a_report_is_a_result_not_a_failure(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}")
    run = lambda *a, **k: FakeProc(json.dumps({"vulnerabilities": {"a": {}}}), returncode=1)  # noqa: E731
    code, merged, problems = auditrun.run_audits("npm", tmp_path, run=run)
    assert code == 0 and not problems and merged["audits"][0]["dir"] == "."


@pytest.mark.parametrize("proc", [
    FakeProc(json.dumps({"error": {"code": "ENOTFOUND", "summary": "registry unreachable"}}), returncode=1),
    FakeProc("", "npm ERR! network", returncode=1),
    FakeProc("not json", returncode=0),
    FakeProc("{}", returncode=0),  # valid JSON but not an audit report
    FakeProc(json.dumps({"vulnerabilities": {}}), returncode=2),
])  # fmt: skip
def test_an_audit_that_did_not_happen_fails_the_whole_run(tmp_path, proc):
    (tmp_path / "package-lock.json").write_text("{}")
    code, _, problems = auditrun.run_audits("npm", tmp_path, run=lambda *a, **k: proc)
    assert code == auditrun.EXIT_FAILED and problems


def test_one_broken_folder_is_not_hidden_by_a_good_one(tmp_path):
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "package-lock.json").write_text("{}")
    answers = iter([FakeProc(json.dumps({"vulnerabilities": {}})), FakeProc("", "boom", 1)])
    code, _, problems = auditrun.run_audits("npm", tmp_path, run=lambda *a, **k: next(answers))
    assert code == auditrun.EXIT_FAILED and len(problems) == 1 and problems[0].startswith("b:")


def test_no_lockfile_is_a_skip(tmp_path):
    code, _, _ = auditrun.run_audits("npm", tmp_path)
    assert code == auditrun.EXIT_NO_LOCKFILE


def test_the_command_is_a_list_never_a_shell(tmp_path):
    seen = {}

    def run(cmd, **kw):
        seen.update(cmd=cmd, **kw)
        return FakeProc(json.dumps({"vulnerabilities": {}}))

    (tmp_path / "package-lock.json").write_text("{}")
    auditrun.run_audits("npm", tmp_path, run=run)
    assert isinstance(seen["cmd"], list) and "shell" not in seen and seen["cwd"] == tmp_path


# ----------------------------------------------------------------- through run_tool


def test_tool_command_and_statuses(monkeypatch, tmp_path):
    tool = NpmAudit()
    cmd = tool.local_cmd(str(tmp_path), ScanOptions(excludes=("old",)))
    assert cmd[:3] == [sys.executable, "-m", "polyscan.auditrun"] and cmd[-2:] == ["--exclude", "old"]

    def fake(code, out="", err=""):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc(out, err, code))
        return run_tool(tool, "local", tmp_path, ScanOptions(), 10)

    assert fake(0, NPM).status == OK
    assert fake(4, "", "no package-lock.json found").status == SKIPPED
    r = fake(3, "", "web: ENOTFOUND: registry unreachable")
    assert r.status == ERROR and "ENOTFOUND" in r.detail
    assert fake(0, "").status == ERROR  # empty output is never a clean result


# ----------------------------------------------------------------- cargo

from polyscan.tools import CargoAudit, cvss3_score, parse_cargo_audit, severity_from_score  # noqa: E402

CARGO = (FIX / "cargo-audit.json").read_text(encoding="utf-8")


def test_cargo_real_output():
    (f,) = parse_cargo_audit(CARGO, "/proj")
    assert f.rule == "RUSTSEC-2020-0071" and f.file == "rust/Cargo.lock" and f.category == "dependency"
    assert f.message.startswith("time 0.1.43: Potential segfault") and ">=0.2.23" in f.message
    assert f.severity == Severity.MEDIUM  # CVSS 6.2, computed from the vector


@pytest.mark.parametrize("vector,score", [  # scores published in the CVSS specification and NVD
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])  # fmt: skip
def test_cvss_scores(vector, score):
    assert cvss3_score(vector) == score


@pytest.mark.parametrize("vector", ["", "CVSS:4.0/AV:N", "CVSS:3.1/AV:N", "garbage", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
def test_a_vector_that_cannot_be_read_gives_no_score_and_medium(vector):
    assert cvss3_score(vector) is None
    assert severity_from_score(None) == Severity.MEDIUM


def test_score_to_severity_boundaries():
    got = [severity_from_score(s) for s in (0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)]
    assert got == [Severity.INFO, Severity.LOW, Severity.LOW, Severity.MEDIUM, Severity.MEDIUM,
                   Severity.HIGH, Severity.HIGH, Severity.CRITICAL, Severity.CRITICAL]  # fmt: skip


def test_cargo_warnings_are_reported_not_ignored():
    # The "warnings" shape follows cargo-audit's documented output; the demo project has none, so this is synthetic.
    report = {"vulnerabilities": {"list": []}, "warnings": {
        "unmaintained": [{"kind": "unmaintained", "package": {"name": "old", "version": "1.0.0"},
                          "advisory": {"id": "RUSTSEC-2099-0001", "title": "old is unmaintained"}}],
        "yanked": [{"kind": "yanked", "package": {"name": "gone", "version": "0.3.1"}, "advisory": None}],
    }}  # fmt: skip
    data = {"kind": "cargo", "audits": [{"dir": ".", "lockfile": "Cargo.lock", "report": report}]}
    unmaintained, yanked = parse_cargo_audit(json.dumps(data), "/p")
    assert unmaintained.rule == "RUSTSEC-2099-0001" and unmaintained.file == "Cargo.lock"
    assert yanked.rule == "yanked" and "gone 0.3.1" in yanked.message
    assert unmaintained.severity == yanked.severity == Severity.LOW


def test_cargo_tool_wiring(monkeypatch, tmp_path):
    tool = CargoAudit()
    assert tool.binary == "cargo-audit" and tool.languages == frozenset({"rust"})
    assert tool.local_cmd(str(tmp_path), ScanOptions())[3] == "cargo"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc(CARGO, "", 0))
    assert run_tool(tool, "local", tmp_path, ScanOptions(), 10).status == OK


def test_cargo_command_uses_the_cargo_audit_program():
    assert auditrun.KINDS["cargo"][1][:2] == ["cargo-audit", "audit"]
