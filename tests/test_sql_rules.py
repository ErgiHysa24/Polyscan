"""The built-in SQL injection rules: command wiring and real Semgrep runs."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from polyscan.scanner import build_command
from polyscan.tools import RULES_DIR, ScanOptions, Semgrep, parse_semgrep

HERE = Path(__file__).parent
needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")


def test_rules_ship_with_the_package():
    assert (RULES_DIR / "sql-injection.yml").is_file()


def test_builtin_rules_are_loaded_by_default_locally():
    cmd = build_command(Semgrep(), "local", Path("/p"), ScanOptions())
    assert any(a.endswith("sql-injection.yml") for a in cmd)


def test_builtin_rules_can_be_turned_off():
    cmd = build_command(Semgrep(), "local", Path("/p"), ScanOptions(builtin_rules=False))
    assert not any("sql-injection" in a for a in cmd)


def test_docker_mounts_the_rules_read_only():
    root = Path("/work/proj")
    cmd = build_command(Semgrep(), "docker", root, ScanOptions())
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert f"{root}:/src:ro" in mounts
    assert f"{RULES_DIR}:/rules:ro" in mounts
    assert "/rules/sql-injection.yml" in cmd


def test_docker_has_no_rules_mount_when_turned_off():
    cmd = build_command(Semgrep(), "docker", Path("/work/proj"), ScanOptions(builtin_rules=False))
    assert [a for a in cmd if a == "-v"] == ["-v"]


@pytest.mark.parametrize(
    "raw",
    [
        "tests.sql.polyscan-sql-python",
        "home.claude.polyscan.polyscan.rules.polyscan-sql-java",
        "rules.polyscan-sql-php",
    ],
)
def test_rule_id_shows_only_the_stable_part(raw):
    out = json.dumps({"results": [{"check_id": raw, "path": "/ROOT/a.py", "start": {"line": 1}, "extra": {"message": "m", "severity": "ERROR"}}]})
    assert parse_semgrep(out, "/ROOT")[0].rule == raw[raw.index("polyscan-"):]


def test_registry_rule_ids_are_left_alone():
    rid = "python.flask.security.injection.tainted-sql-string.tainted-sql-string"
    out = json.dumps({"results": [{"check_id": rid, "path": "a.py", "start": {"line": 1}, "extra": {}}]})
    assert parse_semgrep(out, "/ROOT")[0].rule == rid


@needs_semgrep
def test_rules_pass_their_own_examples():
    """Every `# ruleid:` line must be found and every `# ok:` line must stay quiet."""
    proc = subprocess.run(
        ["semgrep", "--test", "--config", str(RULES_DIR), str(HERE / "sql"), "--metrics=off", "--disable-version-check"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "All tests passed" in proc.stdout


@needs_semgrep
def test_end_to_end_through_polyscan_finds_sql_injection_in_all_five_languages(tmp_path):
    for name in ("py", "js", "java", "php", "rs"):
        shutil.copy(HERE / "sql" / f"sql-injection.{name}", tmp_path / f"demo.{name}")
    report = tmp_path / "r.json"
    # --semgrep-config with a local file keeps this test offline (no registry download)
    code = subprocess.run(
        [sys.executable, "-m", "polyscan", "scan", str(tmp_path), "--mode", "local", "--only", "semgrep",
         "--semgrep-config", str(HERE / "rules" / "demo-rules.yml"), "--json", str(report), "--fail-on", "none"],
        capture_output=True, text=True, check=False,
    ).returncode  # fmt: skip
    assert code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    sql = [f for f in data["findings"] if f["rule"].startswith("polyscan-sql-")]
    assert {f["language"] for f in sql} == {"python", "javascript", "java", "php", "rust"}
    assert all(f["rule"].count(".") == 0 for f in sql)  # path prefix stripped
    assert all(f["severity"] == "high" for f in sql)


@needs_semgrep
def test_no_builtin_rules_flag_turns_them_off(tmp_path):
    shutil.copy(HERE / "sql" / "sql-injection.py", tmp_path / "demo.py")
    report = tmp_path / "r.json"
    subprocess.run(
        [sys.executable, "-m", "polyscan", "scan", str(tmp_path), "--mode", "local", "--only", "semgrep",
         "--semgrep-config", str(HERE / "rules" / "demo-rules.yml"), "--no-builtin-rules",
         "--json", str(report), "--fail-on", "none"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    data = json.loads(report.read_text(encoding="utf-8"))
    assert not [f for f in data["findings"] if f["rule"].startswith("polyscan-sql-")]


ISOLATED = {
    # One interpolated query alone in a file. Regression: a regex that matched only
    # "SELECT ... FROM" made these invisible unless other SQL sat nearby in the file.
    "js": 'function f(req) {\n  db.query(`SELECT * FROM users WHERE name = ${req.query.name}`);\n}\n',
    "py": 'def f(name):\n    cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n',
    "php": '<?php\nfunction f($db, $name) {\n    $db->query("SELECT * FROM users WHERE name = \'$name\'");\n}\n',
    "java": 'class A {\n  void f(java.sql.Statement s, String n) throws Exception {\n    s.executeQuery(String.format("SELECT * FROM users WHERE name = \'%s\'", n));\n  }\n}\n',
}
SAFE = {
    "js": 'function f(req) {\n  db.query("SELECT * FROM users WHERE name = ?", [req.query.name]);\n  console.log(`hello ${req.query.name}, welcome`);\n}\n',
    "py": 'def f(name):\n    cur.execute("SELECT * FROM users WHERE name = ?", (name,))\n    print(f"select a {name} from the list")\n',
    "php": '<?php\nfunction f($db, $name) {\n    $db->query("SELECT * FROM users");\n    echo "hello $name";\n}\n',
    "java": 'class A {\n  void f(java.sql.Statement s, String n) throws Exception {\n    s.executeQuery("SELECT * FROM users");\n    System.out.println(String.format("hello %s", n));\n  }\n}\n',
}


def _sql_hits(tmp_path, ext, text):
    src = tmp_path / f"case.{ext}"
    src.write_text(text, encoding="utf-8")
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(RULES_DIR / "sql-injection.yml"), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(src)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    data = json.loads(proc.stdout)
    assert not data["errors"], data["errors"]
    return [r["start"]["line"] for r in data["results"]]


@needs_semgrep
@pytest.mark.parametrize("ext", sorted(ISOLATED))
def test_lone_interpolated_query_is_found(tmp_path, ext):
    assert _sql_hits(tmp_path, ext, ISOLATED[ext]), f"{ext}: SQL injection not detected"


@needs_semgrep
@pytest.mark.parametrize("ext", sorted(SAFE))
def test_lone_safe_code_stays_quiet(tmp_path, ext):
    assert _sql_hits(tmp_path, ext, SAFE[ext]) == []


def test_rule_messages_are_plain_readable_text():
    """Semgrep replaces $1, $X ... inside messages, and a stray backslash shows up in reports."""
    import re

    text = (RULES_DIR / "sql-injection.yml").read_text(encoding="utf-8")
    messages = re.findall(r"message: >-\n\s+(.+)", text)
    assert len(messages) == 5
    for m in messages:
        assert "\\" not in m, m
        assert not re.search(r"\$[0-9]", m), m
