"""Command line interface."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .models import Severity
from .ports import DEFAULT_EXPECTED, check as check_ports
from .report import to_html, to_json, to_markdown, to_terminal
from .risk import DATA, EXPOSURES, LEVELS, Context, assess, load_report, merge
from .riskreport import to_html as risk_html
from .riskreport import to_json as risk_json
from .riskreport import to_markdown as risk_markdown
from .riskreport import to_terminal as risk_terminal
from .scanner import MODES, dast, scan
from .target import TargetError, classify
from .tools import ScanOptions, all_tools, check_auth, pinned_version, site_tools

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
    s.add_argument("--only", metavar="TOOLS", help="comma separated: semgrep,gitleaks,gitleaks-history,osv-scanner,bandit,checkov")
    s.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="folder or file pattern to ignore (repeatable)")  # fmt: skip
    s.add_argument("--semgrep-config", action="append", metavar="CFG",
                   help="Semgrep rules: a registry pack like p/php or a local file (repeatable)")  # fmt: skip
    s.add_argument("--no-builtin-rules", action="store_true",
                   help="do not load polyscan's own Semgrep rules (SQL injection)")  # fmt: skip
    s.add_argument("--history", action="store_true",
                   help="also search old commits for secrets (needs the full git history)")
    s.add_argument("--limit", type=int, default=30, help="findings shown in the terminal (default: 30)")
    s.add_argument("--timeout", type=int, default=900, help="seconds allowed for each tool (default: 900)")

    d = sub.add_parser(
        "dast",
        help="scan a RUNNING site (passive checks with OWASP ZAP). Only for sites you own or may test",
    )
    d.add_argument("url", help="address of the site, for example http://localhost:5000")
    d.add_argument("--allow-remote", action="store_true",
                   help="scan a site that is NOT on your own machine or network. Use it only if you own "
                        "the site or have written authorization to test it")  # fmt: skip
    d.add_argument("--minutes", type=int, default=1, help="minutes the crawler may run, 1 to 30 (default: 1)")
    d.add_argument("--auth-header-env", metavar="VAR",
                   help="name of an ENVIRONMENT VARIABLE holding the value of a header added to every request "
                        "(for example 'Bearer <token>' or 'session=<cookie>'), to scan the pages behind a login. "
                        "The value is never taken from the command line, so it stays out of shell history")  # fmt: skip
    d.add_argument("--auth-header-name", default="Authorization", metavar="NAME",
                   help="header used with --auth-header-env: Authorization (default) or Cookie")
    d.add_argument("--mode", choices=MODES, default="auto", help="ZAP runs only in Docker")
    d.add_argument("--html", metavar="FILE", help="write an HTML report")
    d.add_argument("--json", metavar="FILE", help="write a JSON report")
    d.add_argument("--markdown", metavar="FILE", help="write a short Markdown summary")
    d.add_argument("--fail-on", default="high", choices=[x.label for x in Severity] + ["none"],
                   help="exit with 1 if a finding has this severity or higher (default: high)")  # fmt: skip
    d.add_argument("--strict", action="store_true", help="also exit with 3 if a tool is missing")
    d.add_argument("--limit", type=int, default=30, help="findings shown in the terminal (default: 30)")
    d.add_argument("--timeout", type=int, default=900, help="seconds allowed for ZAP (default: 900)")

    o = sub.add_parser(
        "ports",
        help="which network ports THIS machine is listening on and for whom (reads the list with ss; sends nothing)",
    )
    o.add_argument("--expect", default=",".join(map(str, DEFAULT_EXPECTED)), metavar="PORTS",
                   help="comma-separated ports that are meant to be reachable (default: 22,80,443); these are never "
                        "reported, even if they are a database port. Every other port open to the network is")  # fmt: skip
    o.add_argument("--html", metavar="FILE", help="write an HTML report")
    o.add_argument("--json", metavar="FILE", help="write a JSON report (can be given to `polyscan risk`)")
    o.add_argument("--markdown", metavar="FILE", help="write a short Markdown summary")
    o.add_argument("--fail-on", default="high", choices=[x.label for x in Severity] + ["none"],
                   help="exit with 1 if a finding has this severity or higher (default: high)")  # fmt: skip
    o.add_argument("--strict", action="store_true", help="also exit with 3 if the check could not run (for example not on Linux)")
    o.add_argument("--limit", type=int, default=30, help="findings shown in the terminal (default: 30)")

    r = sub.add_parser(
        "risk",
        help="turn one or more JSON reports (from scan / dast) into a risk register: likelihood x impact, priorities, what to do",
    )
    r.add_argument("reports", nargs="+", metavar="REPORT.json", help="reports written with --json (several can be combined)")
    r.add_argument("--exposure", choices=sorted(EXPOSURES), default="internet",
                   help="who can reach the application (default: internet, the cautious choice)")  # fmt: skip
    r.add_argument("--data", choices=sorted(DATA), default="personal",
                   help="what the application holds: public, internal, or personal (users, passwords, payments). Default: personal")  # fmt: skip
    r.add_argument("--html", metavar="FILE", help="write an HTML report with the risk matrix")
    r.add_argument("--json", metavar="FILE", help="write a JSON report")
    r.add_argument("--markdown", metavar="FILE", help="write a Markdown register")
    r.add_argument("--fail-on", default="none", choices=["none", *LEVELS],
                   help="exit with 1 if a risk has this level or higher (default: none)")  # fmt: skip
    r.add_argument("--strict", action="store_true", help="also exit with 3 if a check of the source reports did not run")
    r.add_argument("--limit", type=int, default=15, help="risks shown in the terminal (default: 15)")

    sub.add_parser("doctor", help="show which tools are available on this computer")
    return p


def cmd_doctor() -> int:
    print(f"polyscan {__version__}")
    docker = shutil.which("docker")
    print(f"  {'docker':<16} {'found' if docker else 'not found'}")
    for t in [*all_tools(), *site_tools()]:
        local = t.local_ok and shutil.which(t.binary)
        note = "found" if local else ("not found; will use Docker" if t.image and docker else "not found")
        if not t.local_ok:
            note = "Docker only" + ("" if docker else " (Docker not found)")
        version = pinned_version(t.image)
        pinned = f"  (Docker image pinned: {version})" if version else ""
        print(f"  {t.name:<16} {note}{pinned}")
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
        history=args.history,
    )
    result = scan(root, args.mode, opts, only, args.timeout)

    return _finish(args, result)


def _finish(args, result) -> int:
    """Print and save the reports, then pick the exit code (shared by scan and dast)."""
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


REFUSAL = """error: {host} ({addresses}) is not on your own machine or network.

Scanning a site you do not own, or do not have written authorization to test, can be
illegal and can disturb the people who run it. polyscan scans only your own machine
and private network by default.

If you OWN this site, or have that authorization in writing, run the command again
with --allow-remote. See "Uso responsabile e autorizzazione" in the README."""


def cmd_dast(args) -> int:
    try:
        target = classify(args.url)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not target.local and not args.allow_remote:
        print(REFUSAL.format(host=target.host, addresses=", ".join(target.addresses)), file=sys.stderr)
        return EXIT_USAGE
    if not 1 <= args.minutes <= 30:
        print("error: --minutes must be between 1 and 30", file=sys.stderr)
        return EXIT_USAGE
    opts = ScanOptions(zap_minutes=args.minutes)
    if args.auth_header_env:
        value = os.environ.get(args.auth_header_env, "")
        try:
            check_auth(args.auth_header_name, value)
        except ValueError as exc:
            # Never fall back to an unauthenticated scan: it would look like a clean result for the protected pages.
            print(f"error: --auth-header-env {args.auth_header_env}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not target.local and urlsplit(args.url).scheme != "https":
            print("error: with a login header, a site that is not on your own network must use https "
                  "(otherwise the secret travels in clear text)", file=sys.stderr)
            return EXIT_USAGE
        opts = replace(opts, auth_name=args.auth_header_name, auth_value=value)
    result = dast(target, args.mode, opts, args.timeout)
    return _finish(args, result)


def cmd_ports(args) -> int:
    try:
        expected = tuple(int(x) for x in args.expect.split(",") if x.strip())
        if not all(0 < p < 65536 for p in expected):
            raise ValueError
    except ValueError:
        print("error: --expect must be a comma-separated list of port numbers (1-65535)", file=sys.stderr)
        return EXIT_USAGE
    return _finish(args, check_ports(expected))


def cmd_risk(args) -> int:
    try:
        ctx = Context(args.exposure, args.data)
        sources = [load_report(path) for path in args.reports]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    risks = assess(merge(sources), ctx)
    print(risk_terminal(ctx, risks, sources, args.limit))
    for path, write, label in ((args.json, risk_json, "JSON"), (args.markdown, risk_markdown, "Markdown"), (args.html, risk_html, "HTML")):
        if path:
            Path(path).write_text(write(ctx, risks, sources), encoding="utf-8")
            print(f"{label} report: {path}")
    if args.fail_on != "none" and any(LEVELS.index(r.level) >= LEVELS.index(args.fail_on) for r in risks):
        return EXIT_FINDINGS
    statuses = {t.get("status") for s in sources for t in s.tools}
    if "error" in statuses or (args.strict and "unavailable" in statuses):
        return EXIT_GAPS  # the register may be incomplete: never look clean
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # old Windows consoles cannot print every character
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return cmd_doctor()
    if args.command == "risk":
        return cmd_risk(args)
    if args.command == "ports":
        return cmd_ports(args)
    return cmd_dast(args) if args.command == "dast" else cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
