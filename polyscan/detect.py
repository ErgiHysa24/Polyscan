"""Find out which languages (and kinds of configuration) a folder contains."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",  # TypeScript is scanned with the JavaScript rules
    ".tsx": "javascript",
    ".java": "java",
    ".php": "php",
    ".rs": "rust",
}

# Files that tell us a project uses a language even if few sources exist.
MANIFESTS = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile.lock": "python",
    "poetry.lock": "python",
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "yarn.lock": "javascript",
    "pnpm-lock.yaml": "javascript",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "composer.json": "php",
    "composer.lock": "php",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
}

# Configuration files are recognised by NAME (a Dockerfile has no extension).
# The result is a "kind" that is counted like a language, so tools can say
# "run me only if the project has Docker files".
CONFIG_NAMES = {
    "docker": (
        "Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.dockerfile",
        "docker-compose.yml", "docker-compose.yaml", "docker-compose.*.yml", "docker-compose.*.yaml",
        "compose.yml", "compose.yaml",
    ),
    "terraform": ("*.tf",),
}  # fmt: skip


def config_kind(filename: str) -> str:
    for kind, patterns in CONFIG_NAMES.items():
        if any(fnmatch.fnmatchcase(filename, pat) for pat in patterns):
            return kind
    return ""


# Folders full of third-party or generated code. Scanning them is slow and
# produces findings the project owner cannot fix.
DEFAULT_EXCLUDES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "target",
        "build",
        "dist",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)


def detect_languages(root: Path, excludes: frozenset[str] = DEFAULT_EXCLUDES) -> dict[str, int]:
    """Return {language: number of matching files} for the folder tree.

    Symlinks are not followed, so a link cannot make us leave `root`.
    """
    counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not any(fnmatch.fnmatch(d, p) for p in excludes)]
        for name in filenames:
            lang = MANIFESTS.get(name) or EXTENSIONS.get(os.path.splitext(name)[1].lower()) or config_kind(name)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items()))
