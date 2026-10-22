"""Run the tools on a folder and collect their results."""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from .detect import DEFAULT_EXCLUDES, detect_languages
from .models import ERROR, OK, SKIPPED, UNAVAILABLE, Finding, ToolResult
from .tools import CONTAINER_ROOT, ScanOptions, Tool, all_tools, scan_errors

MODES = ("auto", "docker", "local")


@dataclass
class ScanResult:
    root: str
    languages: dict[str, int]
    tools: list[ToolResult] = field(default_factory=list)
    mode: str = "auto"

    @property
    def findings(self) -> list[Finding]:
        out = [f for t in self.tools for f in t.findings]
        return sorted(out, key=lambda f: (-int(f.severity), f.file, f.line, f.rule))

    @property
    def had_errors(self) -> bool:
        return any(t.status == ERROR for t in self.tools)

    @property
    def had_gaps(self) -> bool:
        """True if some check did not happen (tool failed or was missing)."""
        return any(t.status in (ERROR, UNAVAILABLE) for t in self.tools)


def _tail(text: str, limit: int = 400) -> str:
    text = " ".join(text.split())
    return text[-limit:]


def build_command(tool: Tool, how: str, root: Path, opts: ScanOptions) -> list[str]:
    """Return the argv list to run. Never goes through a shell."""
    if how == "local":
        return tool.local_cmd(str(root), opts)
    # Read-only mounts: a scanner can read the project but never change it.
    mounts = [(str(root), CONTAINER_ROOT)] + tool.mounts(opts)
    cmd = ["docker", "run", "--rm"]
    for host, inside in mounts:
        cmd += ["-v", f"{host}:{inside}:ro"]
    return cmd + ["-w", CONTAINER_ROOT, tool.image, *tool.docker_cmd(opts)]


def choose_how(tool: Tool, mode: str) -> tuple[str | None, str]:
    """Decide local or docker for one tool. Returns (how, reason_if_none)."""
    has_local = shutil.which(tool.binary) is not None
    has_docker = shutil.which("docker") is not None and tool.image is not None
    if mode == "local":
        return ("local", "") if has_local else (None, f"{tool.binary} is not installed")
    if mode == "docker":
        if tool.image is None:
            return None, f"{tool.name} has no Docker image; use --mode local"
        return ("docker", "") if has_docker else (None, "Docker is not installed")
    if has_local:
        return "local", ""
    if has_docker:
        return "docker", ""
    why = f"{tool.binary} is not installed" + ("" if tool.image is None else " and Docker is missing")
    return None, why


def is_excluded(path: str, patterns: tuple[str, ...]) -> bool:
    """True if any folder of the path, or the path itself, matches a pattern."""
    parts = path.replace("\\", "/").split("/")
    for pat in patterns:
        if any(fnmatch.fnmatch(p, pat) for p in parts) or fnmatch.fnmatch(path, pat):
            return True
    return False


def read_line(root: Path, rel: str, line: int, limit: int = 200) -> str:
    """Read one source line for the report, only from inside the scanned folder."""
    if line <= 0 or not rel:
        return ""
    try:
        path = (root / rel).resolve()
        if root.resolve() not in path.parents:
            return ""  # a path like ../../etc/passwd must never be read
        with path.open(encoding="utf-8", errors="replace") as fh:
            for number, text in enumerate(fh, 1):
                if number == line:
                    return text.strip()[:limit]
    except OSError:
        pass
    return ""


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact repeats (a rule can match the same line twice, e.g. in Rust)."""
    seen = set()
    out = []
    for f in findings:
        key = (f.tool, f.rule, f.file, f.line, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def add_snippets(findings: list[Finding], root: Path) -> list[Finding]:
    """Fill in the code line where the tool gave none (or gave a placeholder)."""
    out = []
    for f in findings:
        if f.category == "code" and (not f.snippet or f.snippet == "requires login"):
            f = replace(f, snippet=read_line(root, f.file, f.line))
        out.append(f)
    return out


def run_tool(tool: Tool, how: str, root: Path, opts: ScanOptions, timeout: int) -> ToolResult:
    cmd = build_command(tool, how, root, opts)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            # Stops Git Bash on Windows from rewriting /src into a Windows path.
            env={**os.environ, "MSYS_NO_PATHCONV": "1"},
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool.name, ERROR, f"timed out after {timeout}s", seconds=time.monotonic() - started)
    except OSError as exc:
        return ToolResult(tool.name, ERROR, f"could not start: {exc}", seconds=time.monotonic() - started)

    seconds = time.monotonic() - started
    if proc.returncode in tool.skip_codes:
        return ToolResult(tool.name, SKIPPED, tool.skip_codes[proc.returncode], seconds=seconds)
    if proc.returncode not in tool.ok_codes:
        return ToolResult(
            tool.name, ERROR, f"exit code {proc.returncode}: {_tail(proc.stderr or proc.stdout)}", seconds=seconds
        )
    if not proc.stdout.strip():
        return ToolResult(
            tool.name, ERROR, f"no output (exit code {proc.returncode}): {_tail(proc.stderr) or 'no error text'}", seconds=seconds
        )
    try:
        findings = tool.parse(proc.stdout, str(root))
    except (ValueError, TypeError, AttributeError) as exc:
        return ToolResult(tool.name, ERROR, f"unreadable output: {exc}", seconds=seconds)
    findings = dedupe([f for f in findings if not is_excluded(f.file, opts.excludes)])
    findings = add_snippets(findings, root)
    detail = f"via {how}"
    if tool.reports_errors:
        problems = scan_errors(proc.stdout)
        if problems:
            detail += f"; {problems} scan error(s): some files may not have been analyzed"
    return ToolResult(tool.name, OK, detail, findings, seconds)


def scan(
    root: Path,
    mode: str = "auto",
    opts: ScanOptions | None = None,
    only: set[str] | None = None,
    timeout: int = 900,
    tools: list[Tool] | None = None,
) -> ScanResult:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    root = root.resolve()
    opts = opts or ScanOptions()
    opts = ScanOptions(
        opts.semgrep_configs, tuple(sorted(set(opts.excludes) | DEFAULT_EXCLUDES)), opts.builtin_rules
    )
    languages = detect_languages(root, frozenset(opts.excludes))
    result = ScanResult(str(root), languages, mode=mode)

    for tool in tools or all_tools():
        if only and tool.name not in only:
            continue
        if not tool.applies(languages):
            result.tools.append(ToolResult(tool.name, SKIPPED, "no matching language found"))
            continue
        how, reason = choose_how(tool, mode)
        if how is None:
            result.tools.append(ToolResult(tool.name, UNAVAILABLE, reason))
            continue
        result.tools.append(run_tool(tool, how, root, opts, timeout))
    return result
