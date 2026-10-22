"""Run the tools on a folder and collect their results."""

from __future__ import annotations

import fnmatch
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from .detect import DEFAULT_EXCLUDES, detect_languages
from .models import ERROR, OK, SKIPPED, UNAVAILABLE, Finding, ToolResult
from .target import Target
from .tools import CONTAINER_ROOT, ScanOptions, Tool, all_tools, scan_errors, site_tools

MODES = ("auto", "docker", "local")


@dataclass
class ScanResult:
    root: str
    languages: dict[str, int]
    tools: list[ToolResult] = field(default_factory=list)
    mode: str = "auto"
    kind: str = "folder"  # folder | site
    notes: list[str] = field(default_factory=list)  # facts the reader must see, e.g. "remote target"

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


def build_command(
    tool: Tool, how: str, root: Path | str, opts: ScanOptions, workdir: Path | None = None, name: str | None = None
) -> list[str]:
    """Return the argv list to run. Never goes through a shell."""
    if how == "local":
        return tool.local_cmd(str(root), opts)
    # Read-only mounts: a scanner can read the project but never change it.
    mounts = ([(str(root), CONTAINER_ROOT)] if tool.uses_folder else []) + tool.mounts(opts)
    cmd = ["docker", "run", "--rm"]
    if name:
        cmd += ["--name", name]  # so that a timed-out run can be stopped by name
    for host, inside in mounts:
        cmd += ["-v", f"{host}:{inside}:ro"]
    if workdir is not None:
        # The only writable mount: a throw-away folder made by polyscan, never the project.
        cmd += ["-v", f"{workdir}:{tool.workdir}:rw"]
    cmd += tool.docker_flags(opts)
    inside_dir = CONTAINER_ROOT if tool.uses_folder else tool.workdir
    return cmd + ["-w", inside_dir, tool.image, *tool.docker_cmd(opts)]


def choose_how(tool: Tool, mode: str) -> tuple[str | None, str]:
    """Decide local or docker for one tool. Returns (how, reason_if_none)."""
    has_local = tool.local_ok and shutil.which(tool.binary) is not None
    has_docker = shutil.which("docker") is not None and tool.image is not None
    if mode == "local":
        if not tool.local_ok:
            return None, f"{tool.name} runs only in Docker; use --mode docker or auto"
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
        if f.category in ("code", "config") and (not f.snippet or f.snippet == "requires login"):
            f = replace(f, snippet=read_line(root, f.file, f.line))
        out.append(f)
    return out


def _stop_container(name: str) -> None:
    """Best effort: `docker run` killed by a timeout leaves the container running."""
    try:
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _hide(text: str, opts: ScanOptions) -> str:
    """Whatever a tool prints, the secret header value never reaches a report or the screen."""
    if opts.auth_value and text:
        return text.replace(opts.auth_value, "[hidden]")
    return text


def run_tool(tool: Tool, how: str, root: Path | str, opts: ScanOptions, timeout: int) -> ToolResult:
    started = time.monotonic()
    name = f"polyscan-{tool.name}-{secrets.token_hex(4)}" if how == "docker" else None
    with tempfile.TemporaryDirectory(prefix="polyscan-") as tmp:
        workdir = None
        if tool.report_file and how == "docker":
            workdir = Path(tmp)
            workdir.chmod(0o777)  # the container's user is not ours; this folder holds only the report
        try:
            stdin = tool.stdin_text(opts)
        except ValueError as exc:  # the message never contains the secret
            return ToolResult(tool.name, ERROR, f"could not prepare the run: {exc}", seconds=time.monotonic() - started)
        cmd = build_command(tool, how, root, opts, workdir, name)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                input=stdin,
                timeout=timeout,
                check=False,
                # Stops Git Bash on Windows from rewriting /src into a Windows path.
                env={**os.environ, "MSYS_NO_PATHCONV": "1"},
            )
        except subprocess.TimeoutExpired:
            if name:
                _stop_container(name)
            return ToolResult(tool.name, ERROR, f"timed out after {timeout}s", seconds=time.monotonic() - started)
        except OSError as exc:
            return ToolResult(tool.name, ERROR, f"could not start: {exc}", seconds=time.monotonic() - started)

        proc.stdout, proc.stderr = _hide(proc.stdout, opts), _hide(proc.stderr, opts)
        output = proc.stdout
        if tool.report_file and proc.returncode in tool.ok_codes:
            # The tool wrote its report to a file. A missing file is a failure, never "no findings".
            report = Path(tmp) / tool.report_file
            try:
                output = report.read_text(encoding="utf-8", errors="replace")
            except OSError:
                output = ""
            output = _hide(output, opts)
            if not output.strip():
                return ToolResult(
                    tool.name, ERROR,
                    f"no report file (exit code {proc.returncode}): {_tail(proc.stdout or proc.stderr) or 'no output'}",
                    seconds=time.monotonic() - started,
                )  # fmt: skip

    seconds = time.monotonic() - started
    if proc.returncode in tool.skip_codes:
        return ToolResult(tool.name, SKIPPED, tool.skip_codes[proc.returncode], seconds=seconds)
    if proc.returncode not in tool.ok_codes:
        return ToolResult(
            tool.name, ERROR, f"exit code {proc.returncode}: {_tail(proc.stderr or proc.stdout)}", seconds=seconds
        )
    if not output.strip():
        return ToolResult(
            tool.name, ERROR, f"no output (exit code {proc.returncode}): {_tail(proc.stderr) or 'no error text'}", seconds=seconds
        )
    try:
        findings = tool.parse(output, str(root))
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        return ToolResult(tool.name, ERROR, f"unreadable output: {exc!r}", seconds=seconds)
    findings = dedupe([f for f in findings if not is_excluded(f.file, opts.excludes)])
    if tool.uses_folder:
        findings = add_snippets(findings, Path(root))
    detail = f"via {how}"
    if tool.reports_errors:
        problems = scan_errors(output)
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
    opts = replace(opts, excludes=tuple(sorted(set(opts.excludes) | DEFAULT_EXCLUDES)))
    languages = detect_languages(root, frozenset(opts.excludes))
    result = ScanResult(str(root), languages, mode=mode)

    for tool in all_tools() if tools is None else tools:
        if (only and tool.name not in only) or not tool.wanted(opts):
            continue
        if not tool.applies(languages):
            result.tools.append(ToolResult(tool.name, SKIPPED, "no matching language found"))
            continue
        problem = tool.precheck(root)
        if problem:
            # The person asked for this check and it cannot run: that is a gap, not a clean result.
            result.tools.append(ToolResult(tool.name, UNAVAILABLE, problem))
            continue
        how, reason = choose_how(tool, mode)
        if how is None:
            result.tools.append(ToolResult(tool.name, UNAVAILABLE, reason))
            continue
        result.tools.append(run_tool(tool, how, root, opts, timeout))
    return result


def dast(
    target: Target,
    mode: str = "auto",
    opts: ScanOptions | None = None,
    timeout: int = 900,
    tools: list[Tool] | None = None,
) -> ScanResult:
    """Scan a RUNNING site. Whether the target may be scanned (local, or remote with
    the person's explicit statement) is decided by the caller, before this runs."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    # Inside a container "localhost" is the container itself, so the tool is given the
    # address of the host machine instead; the report still shows the original URL.
    opts = replace(opts or ScanOptions(), target_url=target.for_container())
    result = ScanResult(target.url, {}, mode=mode, kind="site")
    if not target.local:
        result.notes.append(
            "REMOTE TARGET: this site is not on your own machine or network. It was scanned because "
            "--allow-remote was given, which means you stated that you own it or have written "
            "authorization to test it."
        )
    if opts.auth_value:
        result.notes.append(
            f"AUTHENTICATED SCAN: the header '{opts.auth_name}' (value hidden) was added to every request, "
            "so pages behind the login were visible to the scan. Use a test account with the least "
            "privileges possible, never a real administrator."
        )
    for tool in site_tools() if tools is None else tools:
        how, reason = choose_how(tool, mode)
        if how is None:
            result.tools.append(ToolResult(tool.name, UNAVAILABLE, reason))
            continue
        result.tools.append(run_tool(tool, how, target.url, opts, timeout))
    return result
