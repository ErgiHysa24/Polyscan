"""Command line interface."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .report import to_html, to_json, to_markdown, to_terminal
from .scanner import MODES, scan
from .tools import ScanOptions, all_tools

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_GAPS = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="polyscan",
        description="Run security scanners for Python, JavaScript, Java, PHP and Rust in one go.",
    )
    p.add_argument("--version", action="version", version=f"polyscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a folder")
    s.add_argument("path", nargs="?", default=".", help="folder to scan (default: current folder)")
    s.add_argument("--mode", choices=MODES, default="auto",
                   help="auto: use installed tools, else Docker (default); docker; local")  # fmt: skip
    s.add_argument("--html", metavar="FILE", help="write an HTML report")
    s.add_argument("--json", metavar="FILE", help="write a JSON report")
    s.add_argument("--markdown", metavar="FILE", help="write a short Markdown summary (for GitHub job pages)")
    s.add_argument("--fail-on", default="high", choices=[x.label for x in Severity] + ["none"],
                   help="exit with 1 if a finding has this severity or higher (default: high)")  # fmt: skip
    s.add_argument("--strict", action="store_true",
                   help="also exit with 3 if a tool is missing, not only when it fails")  # fmt: skip
    s.add_argument("--only", metavar="TOOLS", help="comma separated: semgrep,gitleaks,osv-scanner,bandit")
    s.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="folder or file pattern to ignore (repeatable)")  # fmt: skip
    s.add_argument("--semgrep-config", action="append", metavar="CFG",
                   help="Semgrep rules: a registry pack like p/php or a local file (repeatable)")  # fmt: skip
    s.add_argument("--no-builtin-rules", action="store_true",
                   help="do not load polyscan's own Semgrep rules (SQL injection)")  # fmt: skip
    s.add_argument("--limit", type=int, default=30, help="findings shown in the terminal (default: 30)")
    s.add_argument("--timeout", type=int, default=900, help="seconds allowed for each tool (default: 900)")

    sub.add_parser("doctor", help="show which tools are available on this computer")
    return p


def cmd_doctor() -> int:
    print(f"polyscan {__version__}")
    docker = shutil.which("docker")
    print(f"  docker       {'found' if docker else 'not found'}")
    for t in all_tools():
        local = shutil.which(t.binary)
        note = "found" if local else ("not found; will use Docker" if t.image and docker else "not found")
        print(f"  {t.name:<12} {note}")
    print("\nThe 'found' state of Docker does not prove the Docker service is running.")
    return EXIT_OK


def cmd_scan(args) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {args.path} is not a folder", file=sys.stderr)
        return EXIT_USAGE
    only = {x.strip() for x in args.only.split(",") if x.strip()} if args.only else None
    known = {t.name for t in all_tools()}
    if only and only - known:
        print(f"error: unknown tool(s): {', '.join(sorted(only - known))}", file=sys.stderr)
        return EXIT_USAGE

    defaults = ScanOptions()
    opts = ScanOptions(
        semgrep_configs=tuple(args.semgrep_config) if args.semgrep_config else defaults.semgrep_configs,
        excludes=tuple(args.exclude),
        builtin_rules=not args.no_builtin_rules,
    )
    result = scan(root, args.mode, opts, only, args.timeout)

    print(to_terminal(result, args.limit))
    if args.json:
        Path(args.json).write_text(to_json(result), encoding="utf-8")
        print(f"\nJSON report: {args.json}")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(result), encoding="utf-8")
    if args.html:
        Path(args.html).write_text(to_html(result), encoding="utf-8")
        print(f"HTML report: {args.html}")

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return EXIT_FINDINGS
    if result.had_errors or (args.strict and result.had_gaps):
        return EXIT_GAPS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # old Windows consoles cannot print every character
    args = build_parser().parse_args(argv)
    return cmd_doctor() if args.command == "doctor" else cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
