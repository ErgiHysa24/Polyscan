"""SBOM: the list of every library the project depends on, in the CycloneDX format.

    polyscan sbom FOLDER --output sbom.cdx.json

A Software Bill of Materials answers "what is inside this application?" - the question asked every
time a new vulnerability comes out (was log4j in there?). CycloneDX (an OWASP standard) is the format
read by Dependency-Track, DefectDojo and GitHub. polyscan does not write the SBOM itself: it runs
Trivy (the pinned image already used for container scanning) on the folder, mounted READ-ONLY, with
vulnerability scanning off, and checks that what comes back really is a CycloneDX document with
components in it. A failed or empty SBOM is an error, never an empty-but-valid-looking file.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .tools import image_ref

TIMEOUT = 600


def command(root: Path) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", "none",  # an inventory of local files needs no network
        "-v", f"{root}:/src:ro", image_ref("trivy"),
        "fs", "--format", "cyclonedx", "--quiet", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "/src",
    ]  # fmt: skip


def check(data) -> tuple[int, str]:
    """(number of library components, problem). A document without components is a problem."""
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX" or not data.get("specVersion"):
        return 0, "the output is not a CycloneDX document"
    libs = [c for c in data.get("components") or [] if isinstance(c, dict) and c.get("type") == "library"]
    if not libs:
        return 0, "the SBOM lists no library: no lockfile or manifest was recognised"
    return len(libs), ""


def generate(root: Path, run=subprocess.run) -> tuple[dict | None, int, str]:
    """(document, number of libraries, problem)."""
    root = root.resolve()
    if not root.is_dir():
        return None, 0, f"{root} is not a folder"
    try:
        proc = run(command(root), capture_output=True, text=True, errors="replace", timeout=TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return None, 0, f"timed out after {TIMEOUT}s"
    except OSError as exc:
        return None, 0, f"could not start docker ({exc}): the SBOM needs Docker"
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        data = None
    if proc.returncode != 0 or data is None:
        text = " ".join((proc.stderr or proc.stdout or "no output").split())[-300:]
        return None, 0, f"trivy exit code {proc.returncode}: {text}"
    count, why = check(data)
    return (data if not why else None), count, why
