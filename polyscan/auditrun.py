"""Runs `npm audit` / `cargo audit` once for every lockfile in a project and merges the answers.

Why a separate small program instead of calling npm directly: a project can hold
several lockfiles (a backend and a frontend folder, say), and both audit tools look
at ONE folder. polyscan runs each tool as one command, so this wrapper does the
looping and prints a single JSON document that the parser reads.

    python -m polyscan.auditrun npm|cargo|composer FOLDER [--exclude PATTERN]...

Rules kept from the rest of polyscan:
  * no shell: every command is a list of arguments;
  * nothing is installed and no project script runs (`audit` only reads the lockfile);
  * a folder whose audit could NOT be done makes the whole run fail (exit 3), because
    an audit that did not happen must never look like a clean one;
  * exit 4 = there is no lockfile at all (the tool is skipped, not failed).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .detect import DEFAULT_EXCLUDES
from .scanner import is_excluded

KINDS = {
    # kind: (lockfile name, command, key that proves the answer is a real report)
    "npm": ("package-lock.json", ["npm", "audit", "--json"], "vulnerabilities"),
    "cargo": ("Cargo.lock", ["cargo-audit", "audit", "--json"], "vulnerabilities"),
    "composer": ("composer.lock", ["composer", "audit", "--format=json", "--locked"], "advisories"),
}
# Exit codes that still come with a real report. composer's is a bitmask: 1 = advisories, 2 = abandoned packages.
REPORT_CODES = {"npm": (0, 1), "cargo": (0, 1), "composer": (0, 1, 2, 3)}
SKIP_DIRS = DEFAULT_EXCLUDES | {"target"}  # (vendor is already in DEFAULT_EXCLUDES)
EXIT_FAILED, EXIT_NO_LOCKFILE = 3, 4


def find_lock_dirs(root: Path, lockfile: str, excludes: tuple[str, ...] = ()) -> list[Path]:
    """Folders under `root` that hold the lockfile. Symlinks are not followed."""
    found = []
    for here, dirs, files in os.walk(root, followlinks=False):
        rel = Path(here).relative_to(root).as_posix()
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not is_excluded(f"{rel}/{d}".lstrip("./"), excludes))
        if lockfile in files and not is_excluded(rel, excludes):
            found.append(Path(here))
    return sorted(found)


def audit_one(kind: str, folder: Path, run=subprocess.run, timeout: int = 300) -> tuple[dict | None, str]:
    """Returns (report, "") or (None, why it failed). Both tools exit 1 when they FIND something."""
    _, cmd, key = KINDS[kind]
    try:
        proc = run(cmd, cwd=folder, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as exc:
        return None, f"could not start {cmd[0]}: {exc}"
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        data = None
    if isinstance(data, dict) and isinstance(data.get("error"), dict):  # npm: {"error": {"code", "summary"}}
        e = data["error"]
        return None, f"{e.get('code', 'error')}: {' '.join(str(e.get('summary', '')).split())[:300]}"
    if proc.returncode not in REPORT_CODES[kind] or not isinstance(data, dict) or key not in data:
        text = " ".join((proc.stderr or proc.stdout or "no output").split())[-300:]
        return None, f"exit code {proc.returncode}: {text}"
    return data, ""


def run_audits(kind: str, root: Path, excludes: tuple[str, ...] = (), run=subprocess.run) -> tuple[int, dict, list[str]]:
    lockfile = KINDS[kind][0]
    folders = find_lock_dirs(root, lockfile, excludes)
    if not folders:
        return EXIT_NO_LOCKFILE, {}, [f"no {lockfile} found"]
    audits, problems = [], []
    for folder in folders:
        rel = folder.relative_to(root).as_posix()
        report, why = audit_one(kind, folder, run)
        if report is None:
            problems.append(f"{rel if rel != '.' else '.'}: {why}")
        else:
            audits.append({"dir": rel, "lockfile": lockfile, "report": report})
    return (EXIT_FAILED if problems else 0), {"kind": kind, "audits": audits}, problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="polyscan.auditrun")
    p.add_argument("kind", choices=sorted(KINDS))
    p.add_argument("folder")
    p.add_argument("--exclude", action="append", default=[])
    args = p.parse_args(argv)
    code, merged, problems = run_audits(args.kind, Path(args.folder), tuple(args.exclude))
    if code:
        print("; ".join(problems), file=sys.stderr)
        return code
    json.dump(merged, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
