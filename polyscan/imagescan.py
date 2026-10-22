"""Finds the Docker images a project uses and checks each one with Trivy.

    python -m polyscan.imagescan FOLDER [--exclude PATTERN]...

Where the images come from: `FROM` lines of Dockerfiles and `image:` lines of Compose
files. Images the project BUILDS itself (a compose service with only `build:`) are not
scanned: they exist only on the machine that builds them.

Rules kept from the rest of polyscan:
  * no shell: every command is a list of arguments;
  * the project is never mounted into the scanner (Trivy only needs the registry);
  * an image reference comes from a file of the project, so it is checked against a strict
    pattern before it is given to a program (a reference such as `--cache-dir=/` must not
    become an option);
  * Trivy runs the vulnerability scan ONLY (no secret scan: secrets must never be printed);
  * an image that could not be scanned makes the run fail (exit 3), so it never looks clean;
  * exit 4 = no image references at all (the tool is skipped).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .detect import DEFAULT_EXCLUDES, config_kind
from .scanner import is_excluded
from .tools import image_ref

EXIT_FAILED, EXIT_NO_IMAGES = 3, 4
MAX_IMAGES = 20
SEVERITIES = "HIGH,CRITICAL"  # what is worth a decision; MEDIUM and LOW on a base image are mostly noise
REF_OK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}")
FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*(?:#.*)?$", re.IGNORECASE)
COMPOSE_IMAGE_RE = re.compile(r"""^\s*(?:-\s+)?image:\s*(['"]?)([^\s'"#]+)\1\s*(?:#.*)?$""")


@dataclass
class Ref:
    ref: str
    source: str  # file that names the image, relative to the scanned folder
    line: int


def _files(root: Path, excludes: tuple[str, ...]) -> list[Path]:
    found = []
    for here, dirs, names in os.walk(root, followlinks=False):
        rel = Path(here).relative_to(root).as_posix()
        dirs[:] = sorted(d for d in dirs if d not in DEFAULT_EXCLUDES and not is_excluded(f"{rel}/{d}".lstrip("./"), excludes))
        for name in names:
            path = Path(here) / name
            relpath = path.relative_to(root).as_posix()
            if config_kind(name) == "docker" and not is_excluded(relpath, excludes):
                found.append(path)
    return sorted(found)


def refs_in_dockerfile(text: str, source: str) -> tuple[list[Ref], list[Ref]]:
    """(images to scan, references skipped because they contain a variable)."""
    stages: set[str] = set()
    scan, skipped = [], []
    for number, line in enumerate(text.splitlines(), 1):
        m = FROM_RE.match(line)
        if not m:
            continue
        ref, stage = m.group(1), m.group(2)
        if stage:
            stages.add(stage.lower())
        if ref.lower() == "scratch" or ref.lower() in stages - ({stage.lower()} if stage else set()):
            continue  # not an image: an empty base, or an earlier stage of the same Dockerfile
        (skipped if "$" in ref else scan).append(Ref(ref, source, number))
    return scan, skipped


def refs_in_compose(text: str, source: str) -> tuple[list[Ref], list[Ref]]:
    scan, skipped = [], []
    for number, line in enumerate(text.splitlines(), 1):
        m = COMPOSE_IMAGE_RE.match(line)
        if m:
            (skipped if "$" in m.group(2) else scan).append(Ref(m.group(2), source, number))
    return scan, skipped


def find_images(root: Path, excludes: tuple[str, ...] = ()) -> tuple[list[Ref], list[Ref]]:
    scan: dict[str, Ref] = {}
    skipped: list[Ref] = []
    for path in _files(root, excludes):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        source = path.relative_to(root).as_posix()
        is_compose = path.name.lower().startswith(("docker-compose", "compose"))
        found, skip = (refs_in_compose if is_compose else refs_in_dockerfile)(text, source)
        skipped += skip
        for r in found:
            scan.setdefault(r.ref, r)  # one scan per image, attributed to the first place that names it
    return list(scan.values()), skipped


def trivy_command(ref: str, volume: str) -> list[str]:
    """`docker run` of the pinned Trivy image. `--image-src remote`: Trivy fetches the image from the
    registry itself, so no Docker socket is mounted (a mounted socket would be root on this computer)."""
    return [
        "docker", "run", "--rm", "-v", f"{volume}:/root/.cache/trivy", image_ref("trivy"),
        "image", "--quiet", "--format", "json", "--scanners", "vuln", "--severity", SEVERITIES,
        "--image-src", "remote", "--timeout", "10m", ref,
    ]  # fmt: skip


def scan_one(ref: str, volume: str, run=subprocess.run, timeout: int = 900) -> tuple[dict | None, str]:
    try:
        proc = run(trivy_command(ref, volume), capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as exc:
        return None, f"could not start docker: {exc}"
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        data = None
    if proc.returncode != 0 or not isinstance(data, dict) or "SchemaVersion" not in data:
        text = " ".join((proc.stderr or proc.stdout or "no output").split())[-300:]
        return None, f"exit code {proc.returncode}: {text}"
    return data, ""


def run_scan(root: Path, excludes: tuple[str, ...] = (), run=subprocess.run) -> tuple[int, dict, list[str]]:
    images, skipped = find_images(root, excludes)
    if not images and not skipped:
        return EXIT_NO_IMAGES, {}, ["no image references found"]
    if len(images) > MAX_IMAGES:
        return EXIT_FAILED, {}, [f"{len(images)} images found, more than the {MAX_IMAGES} allowed in one run"]
    bad = [r.ref for r in images if not REF_OK.fullmatch(r.ref) or ".." in r.ref]
    if bad:
        return EXIT_FAILED, {}, [f"{r}: not a valid image reference" for r in bad[:5]]
    volume = f"polyscan-trivy-{secrets.token_hex(4)}"  # the vulnerability database is downloaded once and shared
    reports, problems = [], []
    try:
        for r in images:
            report, why = scan_one(r.ref, volume, run)
            if report is None:
                problems.append(f"{r.ref}: {why}")
            else:
                reports.append({"ref": r.ref, "source": r.source, "line": r.line, "report": report})
    finally:
        if images:
            try:
                run(["docker", "volume", "rm", "-f", volume], capture_output=True, timeout=60, check=False)
            except (OSError, subprocess.SubprocessError):
                pass
    merged = {
        "kind": "trivy", "images": reports,
        "skipped": [{"ref": r.ref, "source": r.source, "line": r.line} for r in skipped],
    }  # fmt: skip
    return (EXIT_FAILED if problems else 0), merged, problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="polyscan.imagescan")
    p.add_argument("folder")
    p.add_argument("--exclude", action="append", default=[])
    args = p.parse_args(argv)
    code, merged, problems = run_scan(Path(args.folder), tuple(args.exclude))
    if code:
        print("; ".join(problems), file=sys.stderr)
        return code
    json.dump(merged, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
