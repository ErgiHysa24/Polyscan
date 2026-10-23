"""Runs SpotBugs (Java) and Progpilot (PHP) the careful way and prints one JSON/XML document.

Why a wrapper instead of calling the programs directly: both tools can fail QUIETLY.
Progpilot, tested for real, prints `[]` and exits 0 when a file does not exist or does not
parse. `[]` looks exactly like "no vulnerabilities", so polyscan checks first that every
file is readable PHP, and says which ones were not analyzed. SpotBugs works on COMPILED
classes (not on source), so the wrapper finds them and says clearly when there are none.

    python -m polyscan.sastrun spotbugs FOLDER [--exclude PATTERN]...
    python -m polyscan.sastrun progpilot FOLDER [--exclude PATTERN]...

Rules kept from the rest of polyscan:
  * no shell: every command is a list of arguments, and a file name can never become an option;
  * the scanned project is only READ (nothing is built, installed or executed;
    `php -l` only checks syntax);
  * exit 3 = the analysis could not be done (never printed as "clean"), exit 4 = nothing to analyze.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .scanner import is_excluded

EXIT_FAILED, EXIT_NOTHING = 3, 4
# Walked through when looking for sources. NOT "target"/"build": compiled Java classes live there.
NEVER_ENTER = {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".venv", "venv"}
# Where build tools put the main (non-test) classes.
CLASS_DIR_ENDINGS = (
    ("target", "classes"),  # Maven
    ("build", "classes", "java", "main"),  # Gradle
    ("build", "classes", "kotlin", "main"),
    ("bin", "main"),  # Eclipse/Gradle IDE output
)
PLUGIN_ENV = "POLYSCAN_FINDSECBUGS_JAR"
MAX_PHP_FILES, CHUNK = 5000, 100
FSB_PLUGIN_ID = "com.h3xstream.findsecbugs"


def _walk(root: Path, excludes: tuple[str, ...]):
    """os.walk that does not follow symlinks and skips third-party folders and user excludes."""
    for here, dirs, files in os.walk(root, followlinks=False):
        rel = Path(here).relative_to(root).as_posix()
        dirs[:] = sorted(
            d for d in dirs if d not in NEVER_ENTER and not is_excluded(f"{rel}/{d}".removeprefix("./"), excludes)
        )
        yield Path(here), rel, files


# ------------------------------------------------------------------ SpotBugs
def _has_class_files(folder: Path) -> bool:
    return any(name.endswith(".class") for _, _, names in os.walk(folder, followlinks=False) for name in names)


def find_class_dirs(root: Path, excludes: tuple[str, ...] = ()) -> list[Path]:
    """Folders with compiled MAIN classes (Maven, Gradle, IntelliJ, Eclipse layouts) that hold .class files."""
    found = []
    for here, _rel, _files in _walk(root, excludes):
        parts = here.relative_to(root).parts
        by_ending = any(parts[-len(e):] == e for e in CLASS_DIR_ENDINGS if len(parts) >= len(e))
        intellij = len(parts) >= 3 and parts[-3:-1] == ("out", "production")  # out/production/<module>
        if (by_ending or intellij) and _has_class_files(here):
            found.append(here)
    # keep only the outermost of nested matches
    return [p for p in found if not any(q != p and q in p.parents for q in found)]


def spotbugs_command(class_dirs: list[Path], output: str, plugin_jar: str | None) -> list[str]:
    cmd = ["spotbugs", "-textui", "-xml:withMessages", "-effort:max", "-low", "-output", output]
    if plugin_jar:
        cmd += ["-pluginList", plugin_jar]
    return cmd + [str(d) for d in class_dirs]


def run_spotbugs(root: Path, excludes: tuple[str, ...] = (), run=subprocess.run, timeout: int = 900) -> tuple[int, str, str]:
    """Returns (exit code, XML text, problem text)."""
    # polyscan adds "target" and "build" to the excludes (third-party/generated code), but compiled classes live there
    excludes = tuple(e for e in excludes if e not in ("target", "build"))
    class_dirs = find_class_dirs(root, excludes)
    if not class_dirs:
        return EXIT_NOTHING, "", "no compiled classes found (build the project first, e.g. `mvn compile`)"
    plugin = os.environ.get(PLUGIN_ENV) or None
    if plugin and not Path(plugin).is_file():
        return EXIT_FAILED, "", f"{PLUGIN_ENV} points to a file that does not exist"
    with tempfile.TemporaryDirectory(prefix="polyscan-sb-") as tmp:
        out = str(Path(tmp) / "spotbugs.xml")
        try:
            proc = run(spotbugs_command(class_dirs, out, plugin), capture_output=True, text=True, errors="replace",
                       timeout=timeout, check=False)  # fmt: skip
        except subprocess.TimeoutExpired:
            return EXIT_FAILED, "", f"spotbugs timed out after {timeout}s"
        except OSError as exc:
            return EXIT_FAILED, "", f"could not start spotbugs: {exc}"
        if proc.returncode != 0:
            text = " ".join((proc.stderr or proc.stdout or "no output").split())[-300:]
            return EXIT_FAILED, "", f"spotbugs exit code {proc.returncode}: {text}"
        try:
            xml = Path(out).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return EXIT_FAILED, "", "spotbugs wrote no report file"
    if "<BugCollection" not in xml:
        return EXIT_FAILED, "", "spotbugs report is not a BugCollection"
    if f'id="{FSB_PLUGIN_ID}"' not in xml:
        # Without the plugin SpotBugs only finds general bugs and would look "clean" for security.
        return EXIT_FAILED, "", (
            "the Find Security Bugs plugin was not loaded (set "
            f"{PLUGIN_ENV} to the plugin's jar file)"
        )  # fmt: skip
    return 0, xml, ""


# ------------------------------------------------------------------ Progpilot
def find_php_files(root: Path, excludes: tuple[str, ...] = ()) -> list[Path]:
    found = []
    for here, rel, files in _walk(root, excludes):
        for name in sorted(files):
            rel_file = f"{rel}/{name}".removeprefix("./")
            if name.endswith(".php") and not is_excluded(rel_file, excludes):
                found.append(here / name)
    return found


def _tail(text: str) -> str:
    return " ".join((text or "").split())[-300:]


def syntax_ok(php: str, file: Path, run, timeout: int = 60) -> bool:
    """`php -l` only parses the file. False when it does not parse (or cannot be checked)."""
    try:
        # No "--": php would read the program from standard input instead (found by running it for real).
        # The path is absolute (it starts under the resolved root), so it cannot be read as an option.
        proc = run([php, "-l", str(file)], capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL,
                   timeout=timeout, check=False)  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def run_progpilot(root: Path, excludes: tuple[str, ...] = (), run=subprocess.run, timeout: int = 900) -> tuple[int, dict, str]:
    """Returns (exit code, {"results": [...], "unparsed": [...], "files": N}, problem text)."""
    files = find_php_files(root, excludes)
    if not files:
        return EXIT_NOTHING, {}, "no PHP files found"
    if len(files) > MAX_PHP_FILES:
        return EXIT_FAILED, {}, f"{len(files)} PHP files is more than the {MAX_PHP_FILES} polyscan will check; use --exclude"
    php = shutil.which("php")
    if not php:
        return EXIT_FAILED, {}, "php is needed to check that the files can be parsed, and was not found"
    good, unparsed = [], []
    for f in files:
        (good if syntax_ok(php, f, run) else unparsed).append(f)
    results = []
    for i in range(0, len(good), CHUNK):
        chunk = [str(f) for f in good[i : i + CHUNK]]
        try:
            proc = run(["progpilot", *chunk], capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return EXIT_FAILED, {}, f"progpilot timed out after {timeout}s"
        except OSError as exc:
            return EXIT_FAILED, {}, f"could not start progpilot: {exc}"
        try:
            data = json.loads(proc.stdout)
        except ValueError:
            data = None
        if proc.returncode not in (0, 1) or not isinstance(data, list):
            return EXIT_FAILED, {}, f"progpilot exit code {proc.returncode}: {_tail(proc.stderr or proc.stdout) or 'no output'}"
        results.extend(r for r in data if isinstance(r, dict))
    rel = lambda p: p.relative_to(root).as_posix()  # noqa: E731
    return 0, {"kind": "progpilot", "files": len(good), "unparsed": [rel(f) for f in unparsed], "results": results}, ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="polyscan.sastrun")
    p.add_argument("tool", choices=["spotbugs", "progpilot"])
    p.add_argument("folder")
    p.add_argument("--exclude", action="append", default=[])
    args = p.parse_args(argv)
    root, excludes = Path(args.folder).resolve(), tuple(args.exclude)
    if args.tool == "spotbugs":
        code, xml, why = run_spotbugs(root, excludes)
        if code:
            print(why, file=sys.stderr)
            return code
        sys.stdout.write(xml)
        return 0
    code, data, why = run_progpilot(root, excludes)
    if code:
        print(why, file=sys.stderr)
        return code
    json.dump(data, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
