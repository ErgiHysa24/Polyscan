"""Secrets in git history, with the real Gitleaks."""

import shutil
import subprocess
from pathlib import Path

import pytest

from polyscan.models import OK
from polyscan.scanner import scan
from polyscan.tools import Gitleaks, GitleaksHistory, ScanOptions

needs_tools = pytest.mark.skipif(
    shutil.which("gitleaks") is None or shutil.which("git") is None, reason="gitleaks or git is not installed"
)
DEMO_SETTINGS = Path(__file__).parent.parent / "examples" / "vulnerable-demo" / "python" / "settings.py"


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
                   cwd=cwd, check=True, capture_output=True)  # fmt: skip


@needs_tools
def test_a_deleted_secret_is_found_only_in_the_history(tmp_path):
    git(tmp_path, "init", "-q")
    shutil.copy(DEMO_SETTINGS, tmp_path / "settings.py")  # fake credentials, on purpose
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "add settings")
    git(tmp_path, "rm", "-q", "settings.py")
    (tmp_path / "app.py").write_text("print('clean')\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "remove the key")

    result = scan(tmp_path, "local", ScanOptions(history=True), tools=[Gitleaks(), GitleaksHistory()])
    now, old = result.tools
    assert now.status == OK and now.findings == []  # nothing in today's files
    assert old.status == OK and len(old.findings) >= 1  # but it is in an old commit
    assert all(f.file == "settings.py" and "in commit" in f.message for f in old.findings)
    assert all(f.snippet == "[secret redacted]" for f in old.findings)
