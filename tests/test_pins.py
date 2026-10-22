"""Everything that is downloaded and run must be pinned to something that cannot change.

A tag (`latest`, `v4`) is a label that its owner can move to different content.
A digest or a commit hash identifies the content itself. These tests fail if an
unpinned reference is added, so the protection cannot be lost by accident.
"""

import re
from pathlib import Path

import pytest

from polyscan.scanner import build_command
from polyscan.tools import IMAGES, ScanOptions, all_tools, image_ref, pinned_version

ROOT = Path(__file__).parent.parent
DIGEST_REF = re.compile(r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")
COMMIT_REF = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
FILES_WITH_STEPS = [*sorted((ROOT / ".github" / "workflows").glob("*.yml")), ROOT / "action.yml"]


def test_every_pinned_image_is_a_sha256_digest_with_a_version():
    assert set(IMAGES) == {"semgrep", "gitleaks", "osv-scanner", "checkov"}
    for key, (name, version, digest) in IMAGES.items():
        assert DIGEST_REF.match(f"{name}@{digest}"), key
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"{key}: version {version!r}"
        assert ":latest" not in name


def test_every_tool_with_an_image_uses_a_pinned_one():
    pinned = {image_ref(k) for k in IMAGES}
    with_image = [t for t in all_tools() if t.image]
    assert {t.name for t in with_image} >= {"semgrep", "gitleaks", "osv-scanner", "checkov"}
    for tool in with_image:
        assert tool.image in pinned, f"{tool.name} uses {tool.image}"
        assert pinned_version(tool.image)


def test_docker_command_runs_the_pinned_image(tmp_path):
    for tool in all_tools():
        if tool.image:
            cmd = build_command(tool, "docker", tmp_path, ScanOptions())
            assert tool.image in cmd and DIGEST_REF.match(cmd[cmd.index(tool.image)])


def test_unknown_image_has_no_version():
    assert pinned_version("semgrep/semgrep:latest") == ""
    assert pinned_version(None) == ""


def uses_lines():
    for path in FILES_WITH_STEPS:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"^\s*(?:-\s*)?uses:\s*(\S+)", line)
            if m:
                yield path.name, number, m.group(1), line


def test_there_are_actions_to_check():
    assert sum(1 for _ in uses_lines()) >= 8  # guards against the regex silently matching nothing


@pytest.mark.parametrize("name,number,ref,line", list(uses_lines()))
def test_every_action_is_pinned_to_a_commit_with_its_version_in_a_comment(name, number, ref, line):
    if ref.startswith("./"):
        return  # this repository's own action
    assert COMMIT_REF.match(ref), f"{name}:{number} {ref} is not pinned to a 40-character commit"
    assert re.search(r"#\s*v\d+\.\d+\.\d+\s*$", line), f"{name}:{number} needs a `# vX.Y.Z` comment"


def pip_installs():
    for path in FILES_WITH_STEPS:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "pip install" in line:
                args = line.split("pip install", 1)[1].split()
                yield path.name, number, args


def test_pip_installs_of_tools_name_an_exact_version():
    seen = 0
    for name, number, args in pip_installs():
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg == "-e":  # the project itself, followed by its path
                skip_next = True
                continue
            if arg.startswith(("-", '"', "$", ".")):
                continue  # options and local paths
            seen += 1
            assert re.fullmatch(r"[A-Za-z0-9_.-]+==\d+(\.\d+)*", arg), f"{name}:{number} `{arg}` has no exact version"
    assert seen >= 2  # semgrep in the CI, bandit in the action
