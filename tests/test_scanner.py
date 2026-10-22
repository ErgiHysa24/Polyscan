import sys
from pathlib import Path

from polyscan.models import ERROR, OK, SKIPPED, UNAVAILABLE, Finding, Severity
from polyscan.scanner import build_command, choose_how, is_excluded, run_tool, scan
from polyscan.tools import Gitleaks, OsvScanner, ScanOptions, Semgrep, Tool


class FakeTool(Tool):
    """Runs a tiny Python program instead of a real scanner."""

    def __init__(self, code, ok_codes=(0, 1), skip_codes=None, parse=None, name="fake"):
        super().__init__(
            name, sys.executable, None, parse or (lambda text, root: []),
            ok_codes=ok_codes, skip_codes=skip_codes or {},
        )  # fmt: skip
        self.code = code

    def local_cmd(self, target, opts):
        return [sys.executable, "-c", self.code]


OPTS = ScanOptions()


def one_finding(text, root):
    return [Finding("fake", Severity.HIGH, "r", "m", file="a.py", line=1)]


# ------------------------------------------------------------ commands


def test_docker_command_mounts_read_only_and_uses_no_shell():
    cmd = build_command(Gitleaks(), "docker", Path("/work/proj"), OPTS)
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "/work/proj:/src:ro" in cmd
    assert isinstance(cmd, list)  # a list is run directly, no shell involved
    assert cmd[cmd.index("-w") + 1] == "/src"


def test_semgrep_command_uses_configs_and_excludes():
    opts = ScanOptions(semgrep_configs=("p/php", "rules.yml"), excludes=("tests",))
    cmd = build_command(Semgrep(), "local", Path("/work/proj"), opts)
    assert cmd.count("--config") == 3 and "p/php" in cmd and "rules.yml" in cmd  # 2 + built-in
    assert "--metrics=off" in cmd  # no telemetry
    assert cmd[cmd.index("--exclude") + 1] == "tests"
    assert cmd[-1] == "/work/proj"


def test_a_path_with_shell_characters_stays_one_argument():
    nasty = Path("/work/a; rm -rf ~ #")
    cmd = build_command(OsvScanner(), "local", nasty, OPTS)
    assert cmd[-1] == str(nasty)


def test_gitleaks_never_prints_secrets():
    cmd = build_command(Gitleaks(), "local", Path("/p"), OPTS)
    assert "--redact" in cmd


# -------------------------------------------------------------- choice


def test_choose_how_missing_tool_is_reported(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    how, reason = choose_how(Semgrep(), "auto")
    assert how is None and "not installed" in reason


def test_choose_how_prefers_local_then_docker(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/bin/x")
    assert choose_how(Semgrep(), "auto")[0] == "local"
    monkeypatch.setattr("shutil.which", lambda name: "/bin/docker" if name == "docker" else None)
    assert choose_how(Semgrep(), "auto")[0] == "docker"
    assert choose_how(Semgrep(), "local")[0] is None


def test_bandit_cannot_use_docker(monkeypatch):
    from polyscan.tools import Bandit

    monkeypatch.setattr("shutil.which", lambda name: "/bin/docker" if name == "docker" else None)
    how, reason = choose_how(Bandit(), "docker")
    assert how is None and "no Docker image" in reason


# ----------------------------------------------------------- execution


def test_ok_run_collects_findings(tmp_path):
    res = run_tool(FakeTool("print('{}')", parse=one_finding), "local", tmp_path, OPTS, 30)
    assert res.status == OK and len(res.findings) == 1


def test_tool_crash_is_an_error_not_a_clean_result(tmp_path):
    res = run_tool(FakeTool("import sys; sys.stderr.write('boom'); sys.exit(127)"), "local", tmp_path, OPTS, 30)
    assert res.status == ERROR and "127" in res.detail and "boom" in res.detail
    assert res.findings == []


def test_exit_1_with_no_output_is_an_error_not_a_clean_result(tmp_path):
    """Docker fails with exit code 1 when its service is down. Tools such as
    OSV-Scanner also use 1 for "vulnerabilities found", so exit code alone is
    not enough: a real result always comes with output."""
    code = "import sys; sys.stderr.write('Cannot connect to the Docker daemon'); sys.exit(1)"
    res = run_tool(FakeTool(code, ok_codes=(0, 1)), "local", tmp_path, OPTS, 30)
    assert res.status == ERROR and "Docker daemon" in res.detail


def test_unreadable_output_is_an_error(tmp_path):
    def bad(text, root):
        raise ValueError("bad json")

    res = run_tool(FakeTool("print('x')", parse=bad), "local", tmp_path, OPTS, 30)
    assert res.status == ERROR and "unreadable" in res.detail


def test_skip_code_is_reported_as_skipped(tmp_path):
    tool = FakeTool("import sys; sys.exit(128)", skip_codes={128: "no lockfiles"})
    res = run_tool(tool, "local", tmp_path, OPTS, 30)
    assert res.status == SKIPPED and res.detail == "no lockfiles"


def test_timeout_is_an_error(tmp_path):
    res = run_tool(FakeTool("import time; time.sleep(5)"), "local", tmp_path, OPTS, 1)
    assert res.status == ERROR and "timed out" in res.detail


def test_excluded_paths_are_dropped(tmp_path):
    def parse(text, root):
        return [
            Finding("fake", Severity.LOW, "r", "m", file="src/a.py"),
            Finding("fake", Severity.LOW, "r", "m", file="tests/b.py"),
            Finding("fake", Severity.LOW, "r", "m", file="x/node_modules/c.js"),
        ]

    opts = ScanOptions(excludes=("tests", "node_modules"))
    res = run_tool(FakeTool("print('{}')", parse=parse), "local", tmp_path, opts, 30)
    assert [f.file for f in res.findings] == ["src/a.py"]


def test_is_excluded_matches_folders_and_globs():
    assert is_excluded("a/tests/b.py", ("tests",))
    assert is_excluded("a/b.min.js", ("*.min.js",))
    assert not is_excluded("a/b.py", ("tests",))


# ---------------------------------------------------------- whole scan


def test_scan_reports_every_tool_status(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1")
    monkeypatch.setattr("shutil.which", lambda name: None)  # nothing installed
    res = scan(tmp_path, "auto", tools=[Semgrep(), Gitleaks()])
    assert [t.status for t in res.tools] == [UNAVAILABLE, UNAVAILABLE]
    assert res.had_gaps and not res.had_errors


def test_tool_for_other_language_is_skipped_not_missing(tmp_path, monkeypatch):
    from polyscan.tools import Bandit

    (tmp_path / "a.js").write_text("x")
    monkeypatch.setattr("shutil.which", lambda name: None)
    res = scan(tmp_path, "auto", tools=[Bandit()])
    assert res.tools[0].status == SKIPPED and not res.had_gaps


def test_only_filter(tmp_path):
    res = scan(tmp_path, "local", tools=[FakeTool("print('{}')", name="a"), FakeTool("print('{}')", name="b")], only={"b"})
    assert [t.name for t in res.tools] == ["b"]


# ------------------------------------------------------------ snippets


def test_read_line_returns_the_line(tmp_path):
    from polyscan.scanner import read_line

    (tmp_path / "a.py").write_text("one\n  two  \nthree\n")
    assert read_line(tmp_path, "a.py", 2) == "two"
    assert read_line(tmp_path, "a.py", 99) == ""
    assert read_line(tmp_path, "a.py", 0) == ""


def test_read_line_never_leaves_the_scanned_folder(tmp_path):
    from polyscan.scanner import read_line

    outside = tmp_path / "outside.txt"
    outside.write_text("top secret\n")
    project = tmp_path / "project"
    project.mkdir()
    assert read_line(project, "../outside.txt", 1) == ""
    assert read_line(project, str(outside), 1) == ""


def test_add_snippets_replaces_placeholder_but_never_touches_secrets(tmp_path):
    from polyscan.scanner import add_snippets

    (tmp_path / "a.py").write_text('key = "abc"\n')
    code = Finding("t", Severity.HIGH, "r", "m", file="a.py", line=1, snippet="requires login")
    secret = Finding("t", Severity.HIGH, "r", "m", file="a.py", line=1, category="secret", snippet="[secret redacted]")
    out = add_snippets([code, secret], tmp_path)
    assert out[0].snippet == 'key = "abc"'
    assert out[1].snippet == "[secret redacted]"


def test_scan_errors_are_shown_even_when_the_tool_succeeds(tmp_path):
    tool = FakeTool("print('{\"errors\": [{}, {}]}')")
    tool.reports_errors = True
    res = run_tool(tool, "local", tmp_path, OPTS, 30)
    assert res.status == OK and "2 scan error" in res.detail


def test_identical_findings_are_reported_once(tmp_path):
    def parse(text, root):
        same = Finding("fake", Severity.HIGH, "r", "m", file="a.rs", line=15)
        other_line = Finding("fake", Severity.HIGH, "r", "m", file="a.rs", line=16)
        other_rule = Finding("fake", Severity.HIGH, "r2", "m", file="a.rs", line=15)
        return [same, same, other_line, other_rule]

    res = run_tool(FakeTool("print('{}')", parse=parse), "local", tmp_path, OPTS, 30)
    assert [(f.rule, f.line) for f in res.findings] == [("r", 15), ("r", 16), ("r2", 15)]
