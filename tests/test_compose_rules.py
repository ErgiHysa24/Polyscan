"""The Docker Compose rules, checked against an annotated example file.

`semgrep --test` cannot pair a YAML rule file with a YAML example of the same
name, so this does the same job: a comment `# ruleid: X` says "rule X must report
the next line of code" and `# ok: X` says "rule X must stay quiet there".
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from polyscan.tools import BUILTIN_RULE_FILES, RULES_DIR

HERE = Path(__file__).parent
EXAMPLE = HERE / "compose" / "docker-compose.yml"
needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
ANNOTATION = re.compile(r"^\s*#\s*(ruleid|ok):\s*(\S+)\s*$")


def annotations(path):
    """Return {"ruleid": {(rule, line)}, "ok": {(rule, line)}} where line is the
    first line after the comment that is neither blank nor another comment."""
    lines = path.read_text(encoding="utf-8").splitlines()
    found = {"ruleid": set(), "ok": set()}
    for i, text in enumerate(lines):
        m = ANNOTATION.match(text)
        if not m:
            continue
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or lines[j].lstrip().startswith("#")):
            j += 1
        found[m.group(1)].add((m.group(2), j + 1))  # +1: editors count lines from 1
    return found


def test_the_compose_rules_are_part_of_the_default_rule_set():
    assert "docker-compose.yml" in BUILTIN_RULE_FILES
    assert (RULES_DIR / "docker-compose.yml").is_file()


def test_the_example_file_covers_every_rule():
    ids = re.findall(r"^  - id: (\S+)", (RULES_DIR / "docker-compose.yml").read_text(encoding="utf-8"), re.M)
    wanted = annotations(EXAMPLE)["ruleid"]
    assert len(ids) == 6
    assert {rule for rule, _ in wanted} == set(ids), "every rule needs at least one `# ruleid:` example"


@needs_semgrep
def test_rules_report_exactly_the_annotated_lines():
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(RULES_DIR / "docker-compose.yml"), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(EXAMPLE)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    data = json.loads(proc.stdout)
    assert not data["errors"], data["errors"]
    reported = {(r["check_id"].split(".")[-1], r["start"]["line"]) for r in data["results"]}
    expected = annotations(EXAMPLE)
    assert reported >= expected["ruleid"], f"missed: {sorted(expected['ruleid'] - reported)}"
    assert not reported & expected["ok"], f"false alarm: {sorted(reported & expected['ok'])}"
    assert reported == expected["ruleid"], f"unexpected: {sorted(reported - expected['ruleid'])}"


@needs_semgrep
def test_other_yaml_files_are_not_scanned_by_the_compose_rules(tmp_path):
    (tmp_path / "settings.yml").write_text("privileged: true\nDB_PASSWORD: hunter2\n", encoding="utf-8")
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(RULES_DIR / "docker-compose.yml"), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert json.loads(proc.stdout)["results"] == []
