"""The Docker Compose and Dockerfile rules, checked against annotated example files.

`semgrep --test` cannot pair a rule file with examples whose name or language does
not match, so this does the same job: a comment `# ruleid: X` says "rule X must
report the next line of code" and `# ok: X` says "rule X must stay quiet there".
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from polyscan.tools import BUILTIN_RULE_FILES, RULES_DIR

HERE = Path(__file__).parent
# rule file -> (example files, number of rules in it)
CASES = {
    "docker-compose.yml": (sorted((HERE / "compose").glob("docker-compose*.yml")), 6),
    "dockerfile.yml": (sorted((HERE / "dockerfile").glob("*.Dockerfile")), 7),
}
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


@pytest.mark.parametrize("rule_file", sorted(CASES))
def test_the_rules_are_part_of_the_default_rule_set(rule_file):
    assert rule_file in BUILTIN_RULE_FILES
    assert (RULES_DIR / rule_file).is_file()


def all_annotations(rule_file):
    """Annotations of every example file, with the file name added to each line key."""
    wanted, ok = set(), set()
    for example in CASES[rule_file][0]:
        found = annotations(example)
        wanted |= {(example.name, rule, line) for rule, line in found["ruleid"]}
        ok |= {(example.name, rule, line) for rule, line in found["ok"]}
    return wanted, ok


@pytest.mark.parametrize("rule_file", sorted(CASES))
def test_the_examples_cover_every_rule(rule_file):
    ids = re.findall(r"^  - id: (\S+)", (RULES_DIR / rule_file).read_text(encoding="utf-8"), re.M)
    wanted, _ = all_annotations(rule_file)
    assert len(ids) == CASES[rule_file][1]
    assert {rule for _, rule, _ in wanted} == set(ids), "every rule needs at least one `# ruleid:` example"


@needs_semgrep
@pytest.mark.parametrize("rule_file", sorted(CASES))
def test_rules_report_exactly_the_annotated_lines(rule_file):
    examples = CASES[rule_file][0]
    assert examples, "no example files found"
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(RULES_DIR / rule_file), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", *map(str, examples)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    data = json.loads(proc.stdout)
    assert not data["errors"], data["errors"]
    reported = {(Path(r["path"]).name, r["check_id"].split(".")[-1], r["start"]["line"]) for r in data["results"]}
    wanted, ok = all_annotations(rule_file)
    assert reported >= wanted, f"missed: {sorted(wanted - reported)}"
    assert not reported & ok, f"false alarm: {sorted(reported & ok)}"
    assert reported == wanted, f"unexpected: {sorted(reported - wanted)}"


@needs_semgrep
def test_other_yaml_files_are_not_scanned_by_the_compose_rules(tmp_path):
    (tmp_path / "settings.yml").write_text("privileged: true\nDB_PASSWORD: hunter2\n", encoding="utf-8")
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(RULES_DIR / "docker-compose.yml"), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert json.loads(proc.stdout)["results"] == []


@needs_semgrep
def test_other_file_names_are_not_scanned_by_the_dockerfile_rules(tmp_path):
    (tmp_path / "notes.txt").write_text("FROM python:latest\nENV DB_PASSWORD=abc\n", encoding="utf-8")
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(RULES_DIR / "dockerfile.yml"), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert json.loads(proc.stdout)["results"] == []
