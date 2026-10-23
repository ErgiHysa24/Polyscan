"""Java and PHP tools: composer audit, Progpilot, SpotBugs. Parsers use real CI output (see fixtures/README.md)."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from polyscan import auditrun, sastrun
from polyscan.models import ERROR, OK, SKIPPED, Severity
from polyscan.scanner import run_tool
from polyscan.tools import ComposerAudit, Progpilot, ScanOptions, SpotBugs, all_tools
from polyscan.tools import parse_composer_audit, parse_progpilot, parse_spotbugs

FIX = Path(__file__).parent / "fixtures"
COMPOSER = (FIX / "composer-audit.json").read_text(encoding="utf-8")
PROGPILOT = json.loads((FIX / "progpilot.json").read_text(encoding="utf-8"))
SPOTBUGS = (FIX / "spotbugs.xml").read_text(encoding="utf-8")


def proc(stdout="", stderr="", code=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)


# ------------------------------------------------------------------ composer
def wrap_composer(report=None, directory="php"):
    return json.dumps({"kind": "composer", "audits": [{"dir": directory, "lockfile": "composer.lock",
                                                       "report": report or json.loads(COMPOSER)}]})  # fmt: skip


def test_composer_real_output():
    high, medium = parse_composer_audit(wrap_composer(), "/p")
    assert (high.rule, high.severity) == ("CVE-2026-69246", Severity.HIGH)
    assert medium.severity == Severity.MEDIUM
    assert high.file == "php/composer.lock" and high.category == "dependency" and high.language == "php"
    assert "guzzlehttp/guzzle" in high.message and "<7.15.2" in high.message


def test_composer_abandoned_and_missing_severity():
    report = {"advisories": {"a/b": [{"advisoryId": "PKSA-1", "title": "t", "severity": None}]},
              "abandoned": {"old/pkg": "new/pkg", "dead/pkg": None}}  # fmt: skip
    adv, a1, a2 = parse_composer_audit(wrap_composer(report), "/p")
    assert adv.severity == Severity.MEDIUM and adv.rule == "PKSA-1"
    assert "use new/pkg instead" in a1.message and "no replacement" in a2.message
    assert a1.severity == Severity.LOW


def test_composer_empty_report_is_not_an_error():
    assert parse_composer_audit(wrap_composer({"advisories": [], "abandoned": []}), "/p") == []


def test_composer_rejects_other_output():
    with pytest.raises(ValueError):
        parse_composer_audit('{"kind": "npm", "audits": []}', "/p")


def test_composer_runner_accepts_the_bitmask_exit_codes_and_rejects_the_rest(tmp_path):
    (tmp_path / "composer.lock").write_text("{}")
    for code in (0, 1, 2, 3):
        data, why = auditrun.audit_one("composer", tmp_path, lambda *a, **k: proc(COMPOSER, "", code))
        assert data and not why
    data, why = auditrun.audit_one("composer", tmp_path, lambda *a, **k: proc("", "no network", 100))
    assert data is None and "exit code 100" in why
    # exit 1 but not a report: composer printed an error instead
    data, why = auditrun.audit_one("composer", tmp_path, lambda *a, **k: proc("::error ::Valid composer.lock required", "", 1))
    assert data is None


def test_composer_wiring(tmp_path):
    tool = ComposerAudit()
    assert tool.binary == "composer" and tool.languages == frozenset({"php"})
    assert tool.local_cmd(str(tmp_path), ScanOptions())[3] == "composer"
    assert auditrun.KINDS["composer"][1] == ["composer", "audit", "--format=json", "--locked"]


# ------------------------------------------------------------------ progpilot
def wrap_pp(results=PROGPILOT, unparsed=()):
    return json.dumps({"kind": "progpilot", "files": 1, "unparsed": list(unparsed), "results": results})


def test_progpilot_real_output():
    sql, xss, eval_, cmd = parse_progpilot(wrap_pp(), "/home/runner/work/Polyscan/Polyscan/examples/vulnerable-demo")
    assert sql.file == "php/index.php" and sql.line == 4 and sql.rule == "sql_injection"
    assert (sql.severity, xss.severity, eval_.severity, cmd.severity) == (Severity.HIGH, Severity.MEDIUM, Severity.HIGH, Severity.HIGH)
    assert "CWE-78" in cmd.message and "system" in cmd.message and "_GET" in cmd.message
    assert all(f.tool == "progpilot" and f.language == "php" and f.category == "code" for f in (sql, xss, eval_, cmd))


def test_progpilot_unparsed_files_are_reported_not_hidden():
    (f,) = parse_progpilot(wrap_pp([], ["src/broken.php"]), "/p")
    assert f.rule == "not-analyzed" and f.file == "src/broken.php" and f.severity == Severity.INFO
    assert "NOT checked" in f.message


def test_progpilot_rejects_other_output():
    with pytest.raises(ValueError):
        parse_progpilot("[]", "/p")  # Progpilot's own raw list is not what the wrapper prints


def test_sastrun_progpilot_checks_syntax_first(tmp_path, monkeypatch):
    (tmp_path / "ok.php").write_text("<?php echo 1;")
    (tmp_path / "bad.php").write_text("<?php function (")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.php").write_text("<?php echo 2;")
    monkeypatch.setattr(sastrun.shutil, "which", lambda name: "/usr/bin/php")
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[1] == "-l":
            return proc(code=255 if cmd[-1].endswith("bad.php") else 0)
        return proc("[]", "", 0)

    code, data, why = sastrun.run_progpilot(tmp_path, run=run)
    assert code == 0 and data["unparsed"] == ["bad.php"] and data["files"] == 1
    scanned = [c for c in calls if c[0] == "progpilot"]
    assert len(scanned) == 1 and scanned[0][1:] == [str(tmp_path / "ok.php")]  # vendor and the broken file are not given to it


def test_sastrun_progpilot_failures(tmp_path, monkeypatch):
    assert sastrun.run_progpilot(tmp_path)[0] == sastrun.EXIT_NOTHING
    (tmp_path / "a.php").write_text("<?php echo 1;")
    monkeypatch.setattr(sastrun.shutil, "which", lambda name: None)
    code, _, why = sastrun.run_progpilot(tmp_path)
    assert code == sastrun.EXIT_FAILED and "php is needed" in why
    monkeypatch.setattr(sastrun.shutil, "which", lambda name: "/usr/bin/php")
    ok_lint = lambda cmd, **k: proc(code=0) if cmd[1] == "-l" else proc("not json", "boom", 0)  # noqa: E731
    assert sastrun.run_progpilot(tmp_path, run=ok_lint)[0] == sastrun.EXIT_FAILED
    crashed = lambda cmd, **k: proc(code=0) if cmd[1] == "-l" else proc("", "PHP Fatal", 255)  # noqa: E731
    code, _, why = sastrun.run_progpilot(tmp_path, run=crashed)
    assert code == sastrun.EXIT_FAILED and "255" in why
    # a crash that still printed "[]" must not look like "nothing found"
    empty_crash = lambda cmd, **k: proc(code=0) if cmd[1] == "-l" else proc("[]", "", 255)  # noqa: E731
    assert sastrun.run_progpilot(tmp_path, run=empty_crash)[0] == sastrun.EXIT_FAILED


def test_sastrun_progpilot_file_names_never_become_options(tmp_path, monkeypatch):
    (tmp_path / "-rf.php").write_text("<?php echo 1;")
    monkeypatch.setattr(sastrun.shutil, "which", lambda name: "/usr/bin/php")
    seen = []
    sastrun.run_progpilot(tmp_path, run=lambda cmd, **k: (seen.append(cmd), proc("[]"))[1])
    assert all(str(tmp_path) in c[-1] for c in seen)  # always a full path, never "-rf.php"
    assert seen[0][:2] == ["/usr/bin/php", "-l"] and "--" not in seen[0]  # "php -l --" reads stdin instead of the file


# ------------------------------------------------------------------ spotbugs
def test_spotbugs_real_output_keeps_only_security_bugs(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "App.java").write_text("class App {}")
    cmd, sql, nonconst = parse_spotbugs(SPOTBUGS, str(tmp_path))
    assert (cmd.rule, cmd.severity, cmd.line, cmd.file) == ("COMMAND_INJECTION", Severity.HIGH, 14, "src/App.java")
    assert "CWE-78" in cmd.message and "Runtime.exec" in cmd.message
    assert sql.rule == "SQL_INJECTION_JDBC" and sql.severity == Severity.HIGH and sql.line == 10
    assert nonconst.severity == Severity.HIGH  # priority 1 and an injection CWE
    assert all(f.tool == "spotbugs" and f.language == "java" for f in (cmd, sql, nonconst))
    assert not any("OBL_" in f.rule for f in (cmd, sql, nonconst))  # the EXPERIMENTAL bug is dropped


def test_spotbugs_source_name_when_the_file_is_not_found():
    (f, *_) = parse_spotbugs(SPOTBUGS, "/nonexistent")
    assert f.file == "App.java"


def test_spotbugs_maps_packaged_classes_to_the_right_file(tmp_path):
    for module in ("a", "b"):
        d = tmp_path / module / "src" / "com" / "x"
        d.mkdir(parents=True)
        (d / "App.java").write_text("class App {}")
    (tmp_path / "b" / "src" / "com" / "y").mkdir()
    (tmp_path / "b" / "src" / "com" / "y" / "App.java").write_text("class App {}")
    xml = SPOTBUGS.replace('sourcepath="App.java"', 'sourcepath="com/y/App.java"')
    assert parse_spotbugs(xml, str(tmp_path))[0].file == "b/src/com/y/App.java"


def test_spotbugs_refuses_entity_tricks_and_other_xml():
    with pytest.raises(ValueError):
        parse_spotbugs('<!DOCTYPE x [<!ENTITY a "b">]><BugCollection/>', "/p")
    with pytest.raises(ValueError):
        parse_spotbugs("<html/>", "/p")
    with pytest.raises((ValueError, SyntaxError)):  # ElementTree: ParseError is a SyntaxError
        parse_spotbugs("", "/p")  # empty output is a failure, never "no findings"


def make_classes(root, rel):
    d = root / rel / "com" / "x"
    d.mkdir(parents=True)
    (d / "App.class").write_bytes(b"\xca\xfe\xba\xbe")


def test_find_class_dirs_knows_the_build_layouts(tmp_path):
    make_classes(tmp_path, "svc/target/classes")
    make_classes(tmp_path, "svc/target/test-classes")  # tests are not scanned
    make_classes(tmp_path, "lib/build/classes/java/main")
    make_classes(tmp_path, "ide/out/production/mod")
    make_classes(tmp_path, "node_modules/x/target/classes")
    (tmp_path / "empty" / "target" / "classes").mkdir(parents=True)  # a folder without .class files
    found = sorted(p.relative_to(tmp_path).as_posix() for p in sastrun.find_class_dirs(tmp_path))
    assert found == ["ide/out/production/mod", "lib/build/classes/java/main", "svc/target/classes"]
    assert sastrun.find_class_dirs(tmp_path, ("lib",)) != sastrun.find_class_dirs(tmp_path)


def test_spotbugs_runner_without_classes_is_a_skip_with_a_reason(tmp_path):
    code, _, why = sastrun.run_spotbugs(tmp_path)
    assert code == sastrun.EXIT_NOTHING and "build the project first" in why


def fake_spotbugs(xml, code=0):
    def run(cmd, **kw):
        Path(cmd[cmd.index("-output") + 1]).write_text(xml, encoding="utf-8")
        return proc("", "", code)

    return run


def test_spotbugs_runner_success_and_failures(tmp_path, monkeypatch):
    make_classes(tmp_path, "target/classes")
    monkeypatch.delenv(sastrun.PLUGIN_ENV, raising=False)
    code, xml, _ = sastrun.run_spotbugs(tmp_path, run=fake_spotbugs(SPOTBUGS))
    assert code == 0 and "<BugCollection" in xml
    # SpotBugs failed: never a clean report
    code, _, why = sastrun.run_spotbugs(tmp_path, run=fake_spotbugs("", 1))
    assert code == sastrun.EXIT_FAILED and "exit code 1" in why
    # an empty / foreign report
    assert sastrun.run_spotbugs(tmp_path, run=fake_spotbugs("<html/>"))[0] == sastrun.EXIT_FAILED
    # the security plugin was not loaded: only general bugs were checked, so this must not look clean
    no_plugin = SPOTBUGS.replace('<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>', "")
    code, _, why = sastrun.run_spotbugs(tmp_path, run=fake_spotbugs(no_plugin))
    assert code == sastrun.EXIT_FAILED and "Find Security Bugs plugin was not loaded" in why
    monkeypatch.setenv(sastrun.PLUGIN_ENV, str(tmp_path / "missing.jar"))
    assert "does not exist" in sastrun.run_spotbugs(tmp_path, run=fake_spotbugs(SPOTBUGS))[2]


def test_spotbugs_command_is_an_argument_list(tmp_path):
    cmd = sastrun.spotbugs_command([tmp_path / "x y"], "/o.xml", "/p/fsb.jar")
    assert cmd[:3] == ["spotbugs", "-textui", "-xml:withMessages"] and "-pluginList" in cmd and cmd[-1].endswith("x y")


# ------------------------------------------------------------------ wiring through run_tool
def test_tools_are_registered_for_their_languages():
    by_name = {t.name: t for t in all_tools()}
    assert by_name["spotbugs"].languages == frozenset({"java"})
    assert by_name["progpilot"].languages == frozenset({"php"})
    assert by_name["composer-audit"].languages == frozenset({"php"})
    assert by_name["spotbugs"].applies({"java": 1}) and not by_name["spotbugs"].applies({"php": 1})


@pytest.mark.parametrize("tool, name", [(SpotBugs(), "sastrun"), (Progpilot(), "sastrun"), (ComposerAudit(), "auditrun")])
def test_tools_run_through_the_wrappers(tool, name, tmp_path):
    cmd = tool.local_cmd(str(tmp_path), ScanOptions(excludes=("docs",)))
    assert cmd[:3] == [sys.executable, "-m", f"polyscan.{name}"] and cmd[-2:] == ["--exclude", "docs"]


def test_a_failed_wrapper_is_an_error_and_exit_4_is_a_skip(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc("", "spotbugs exit code 1: boom", 3))
    r = run_tool(SpotBugs(), "local", tmp_path, ScanOptions(), 10)
    assert r.status == ERROR and "boom" in r.detail
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc("", "", 4))
    r = run_tool(SpotBugs(), "local", tmp_path, ScanOptions(), 10)
    assert r.status == SKIPPED and "build the project first" in r.detail
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc(wrap_pp(), "", 0))
    r = run_tool(Progpilot(), "local", tmp_path, ScanOptions(), 10)
    assert r.status == OK and len(r.findings) == 4


@pytest.mark.skipif(not sastrun.shutil.which("php"), reason="php is not installed")
def test_syntax_check_with_the_real_php(tmp_path):
    good, bad = tmp_path / "good.php", tmp_path / "bad.php"
    good.write_text("<?php echo 1;\n")
    bad.write_text("<?php function (\n")
    php = sastrun.shutil.which("php")
    assert sastrun.syntax_ok(php, good, subprocess.run) is True
    assert sastrun.syntax_ok(php, bad, subprocess.run) is False  # the fake-run tests above cannot prove this
    assert sastrun.syntax_ok(php, tmp_path / "missing.php", subprocess.run) is False
    code, data, _ = sastrun.run_progpilot(tmp_path, run=lambda cmd, **k: subprocess.run(cmd, **k) if cmd[1] == "-l" else proc("[]"))
    assert code == 0 and data["unparsed"] == ["bad.php"] and data["files"] == 1


def test_default_excludes_do_not_hide_compiled_classes(tmp_path):
    make_classes(tmp_path, "target/classes")
    seen = []

    def run(cmd, **kw):
        seen.append(cmd)
        return fake_spotbugs(SPOTBUGS)(cmd, **kw)

    code, _, _ = sastrun.run_spotbugs(tmp_path, ("target", "build", "vendor"), run=run)  # what polyscan passes by default
    assert code == 0 and seen[0][-1].endswith("classes")
