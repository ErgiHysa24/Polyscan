"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .models import Severity
from .ports import DEFAULT_EXPECTED
from .ports import check as check_ports
from .report import to_html, to_json, to_markdown, to_terminal
from .risk import DATA, EXPOSURES, LEVELS, Context, Source, assess, load_report, merge
from .intel import gather as gather_intel
from .owasprr import load as load_factors
from .threats import cve_ids
from .treatment import load as load_decisions
from .treatment import template as decisions_template
from .riskreport import to_html as risk_html
from .riskreport import to_json as risk_json
from .riskreport import to_markdown as risk_markdown
from .riskreport import to_terminal as risk_terminal
from .scanner import MODES, dast, scan
from .target import TargetError, classify
from .tools import ScanOptions, all_tools, check_auth, check_login, pinned_version, site_tools

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
    s.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 (GitHub code scanning, DefectDojo, IDEs)")
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
    d.add_argument("--login-url", metavar="URL", help="log in through the site's own form: the URL the form posts to")
    d.add_argument("--login-user", metavar="NAME", help="user name for --login-url (use a test account)")
    d.add_argument("--login-password-env", metavar="VAR", help="name of the environment variable that holds the password")
    d.add_argument("--login-user-field", default="username", metavar="NAME", help="name of the form's user field (default: username)")
    d.add_argument("--login-password-field", default="password", metavar="NAME", help="name of the form's password field (default: password)")
    d.add_argument("--login-check-url", metavar="URL",
                   help="a page only a logged-in user can open (answers 200): the scan is refused if the login did not work")
    d.add_argument("--auth-header-name", default="Authorization", metavar="NAME",
                   help="header used with --auth-header-env: Authorization (default) or Cookie")
    d.add_argument("--mode", choices=MODES, default="auto", help="ZAP runs only in Docker")
    d.add_argument("--html", metavar="FILE", help="write an HTML report")
    d.add_argument("--json", metavar="FILE", help="write a JSON report")
    d.add_argument("--markdown", metavar="FILE", help="write a short Markdown summary")
    d.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0")
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
        help="turn one or more JSON reports (from scan, dast or ports) into a risk register: likelihood x impact, priorities, what to do",
    )
    r.add_argument("reports", nargs="+", metavar="REPORT.json", help="reports written with --json by scan, dast or ports (several can be combined)")
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
    r.add_argument("--decisions", metavar="FILE",
                   help="risk treatment decisions (accept / mitigate / transfer / avoid / false-positive) with owner and dates")  # fmt: skip
    r.add_argument("--intel", action="store_true",
                   help="download CISA KEV and FIRST EPSS to see which CVEs are exploited in the wild (needs internet)")  # fmt: skip
    r.add_argument("--kev-file", metavar="FILE", help="use this CISA KEV catalog (JSON) instead of downloading it")
    r.add_argument("--epss-file", metavar="FILE", help="use these EPSS scores (API JSON or FIRST's CSV) instead of downloading them")
    r.add_argument("--factors", metavar="FILE",
                   help="OWASP Risk Rating factors of your organisation (threat agent, intrusion detection, business impact, overrides)")  # fmt: skip
    r.add_argument("--decisions-template", metavar="FILE",
                   help="write a decisions file with one 'todo' entry per risk, to fill in")  # fmt: skip

    rp = sub.add_parser("report", help="one printable assessment report (scope, executive summary, coverage, risks, treatment, ATT&CK, retest)")
    rp.add_argument("reports", nargs="+", help="JSON reports from scan, dast or ports")
    rp.add_argument("--html", metavar="FILE", required=True, help="where to write the report")
    rp.add_argument("--title", default="Security assessment")
    rp.add_argument("--target", default="", help="what was assessed (application name, URL, version)")
    rp.add_argument("--tester", default="", help="who did the assessment")
    rp.add_argument("--authorized-by", default="", help="who authorized the test (name, role, document)")
    rp.add_argument("--period", default="", help="when the test was done, e.g. 2026-11-10 / 2026-11-14")
    rp.add_argument("--scope", action="append", default=[], help="an item in scope (repeat the option)")
    rp.add_argument("--out-of-scope", action="append", default=[], help="an item explicitly out of scope (repeat)")
    rp.add_argument("--exposure", choices=sorted(EXPOSURES), default="internet")
    rp.add_argument("--data", choices=sorted(DATA), default="personal")
    rp.add_argument("--decisions", metavar="FILE", help="risk treatment decisions (see `polyscan risk`)")
    rp.add_argument("--intel", action="store_true", help="download CISA KEV and FIRST EPSS")
    rp.add_argument("--kev-file", metavar="FILE")
    rp.add_argument("--epss-file", metavar="FILE")
    rp.add_argument("--factors", metavar="FILE", help="OWASP Risk Rating factors (see `polyscan risk --factors`)")
    rp.add_argument("--retest", metavar="BEFORE.json", help="an earlier report: adds the retest section (fixed / still open / new)")
    sb = sub.add_parser("sbom", help="write the list of all dependencies (SBOM) in CycloneDX format, with Trivy in Docker")
    sb.add_argument("path", nargs="?", default=".")
    sb.add_argument("--output", metavar="FILE", required=True, help="where to write the CycloneDX JSON")
    hi = sub.add_parser("history", help="how the findings changed over several scans of the same project")
    hi.add_argument("reports", nargs="+", help="JSON reports of the same project, in any order")
    hi.add_argument("--json", metavar="FILE")
    hi.add_argument("--markdown", metavar="FILE")
    hi.add_argument("--html", metavar="FILE")
    df = sub.add_parser("diff", help="retest: compare two JSON reports (before / after the fixes): fixed, still open, new")
    df.add_argument("before", help="JSON report of the first scan")
    df.add_argument("after", help="JSON report of the scan after the fixes")
    df.add_argument("--json", metavar="FILE", help="write the comparison as JSON")
    df.add_argument("--markdown", metavar="FILE", help="write a Markdown summary")
    df.add_argument("--html", metavar="FILE", help="write an HTML page")
    df.add_argument("--fail-on", choices=["none", *[s.label for s in reversed(Severity)]], default="none",
                    help="exit with 1 if a NEW finding has this severity or higher (default: none)")  # fmt: skip
    df.add_argument("--limit", type=int, default=10, help="findings shown per group in the terminal")
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
    if getattr(args, "sarif", None):
        from .sarif import to_sarif

        Path(args.sarif).write_text(to_sarif(result), encoding="utf-8")
        print(f"SARIF report: {args.sarif}")

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


def _site(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


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
    if args.login_url:
        if args.auth_header_env:
            print("error: use either --login-url (form login) or --auth-header-env (token or cookie), not both", file=sys.stderr)
            return EXIT_USAGE
        opts = replace(opts, login_url=args.login_url, login_user=args.login_user or "",
                       login_password=os.environ.get(args.login_password_env or "", ""),
                       login_user_field=args.login_user_field, login_password_field=args.login_password_field,
                       login_check_url=args.login_check_url or "")  # fmt: skip
        try:
            check_login(opts)
            for label, url in (("--login-url", opts.login_url), ("--login-check-url", opts.login_check_url)):
                # the password must only ever go to the site being tested
                if _site(url) != _site(args.url):
                    raise ValueError(f"{label} must be on the same site as the target ({_site(args.url)})")
        except ValueError as exc:
            print(f"error: form login: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not target.local and urlsplit(args.url).scheme != "https":
            print("error: with a form login, a site that is not on your own network must use https "
                  "(otherwise the password travels in clear text)", file=sys.stderr)
            return EXIT_USAGE
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
        plan = load_decisions(args.decisions) if args.decisions else None
        factors = load_factors(args.factors) if args.factors else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    findings = merge(sources)
    intel = None
    if args.intel or args.kev_file or args.epss_file:
        cves = sorted({c for f in findings for c in cve_ids(f)})
        intel = gather_intel(cves, args.intel, args.kev_file, args.epss_file)
    risks = assess(findings, ctx, plan, intel, factors)
    print(risk_terminal(ctx, risks, sources, args.limit, plan, intel))
    for path, write, label in ((args.json, risk_json, "JSON"), (args.markdown, risk_markdown, "Markdown"), (args.html, risk_html, "HTML")):
        if path:
            Path(path).write_text(write(ctx, risks, sources, plan, intel), encoding="utf-8")
            print(f"{label} report: {path}")
    if args.decisions_template:
        untreated = [r for r in risks if not r.treatment]
        Path(args.decisions_template).write_text(decisions_template(untreated), encoding="utf-8")
        print(f"decisions template ({len(untreated)} risks without a decision): {args.decisions_template}")
    # an accepted (and not expired) risk or a finished treatment no longer fails the build
    if args.fail_on != "none" and any(r.active and LEVELS.index(r.level) >= LEVELS.index(args.fail_on) for r in risks):
        return EXIT_FINDINGS
    statuses = {t.get("status") for s in sources for t in s.tools}
    if "error" in statuses or (args.strict and "unavailable" in statuses) or (intel and intel.problems):
        return EXIT_GAPS  # the register may be incomplete: never look clean
    return EXIT_OK


def cmd_report(args) -> int:
    from . import assessment, diff

    try:
        ctx = Context(args.exposure, args.data)
        sources = [load_report(path) for path in args.reports]
        plan = load_decisions(args.decisions) if args.decisions else None
        before = load_report(args.retest) if args.retest else None
        factors = load_factors(args.factors) if args.factors else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    findings = merge(sources)
    intel = None
    if args.intel or args.kev_file or args.epss_file:
        intel = gather_intel(sorted({c for f in findings for c in cve_ids(f)}), args.intel, args.kev_file, args.epss_file)
    risks = assess(findings, ctx, plan, intel, factors)
    retest = None
    if before:
        # the retest compares against everything read now, as one report
        after = Source("+".join(s.path for s in sources), sources[0].root, sources[0].kind, findings,
                       [t for s in sources for t in s.tools])  # fmt: skip
        retest = diff.compare(before, after)
    meta = assessment.Meta(args.title, args.target, args.tester, args.authorized_by, args.period, args.scope, args.out_of_scope)
    Path(args.html).write_text(assessment.to_html(meta, ctx, risks, sources, plan, intel, retest), encoding="utf-8")
    print(f"assessment report: {args.html} ({len(risks)} risks, {sum(r.active for r in risks)} open)")
    statuses = {t.get("status") for s in sources for t in s.tools}
    return EXIT_GAPS if "error" in statuses or (intel and intel.problems) else EXIT_OK


def cmd_history(args) -> int:
    from . import history

    try:
        sources = [load_report(path) for path in args.reports]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    points = history.build(sources)
    print(history.to_terminal(points))
    for path, write, label in ((args.json, history.to_json, "JSON"), (args.markdown, history.to_markdown, "Markdown"), (args.html, history.to_html, "HTML")):
        if path:
            Path(path).write_text(write(points), encoding="utf-8")
            print(f"{label} report: {path}")
    return EXIT_GAPS if points and points[-1].gaps else EXIT_OK  # the latest scan is incomplete


def cmd_sbom(args) -> int:
    from . import sbom

    data, count, why = sbom.generate(Path(args.path))
    if data is None:
        print(f"error: SBOM not written: {why}", file=sys.stderr)
        return EXIT_GAPS
    Path(args.output).write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(f"SBOM (CycloneDX {data.get('specVersion')}): {args.output} - {count} libraries")
    return EXIT_OK


def cmd_diff(args) -> int:
    from . import diff

    try:
        before, after = load_report(args.before), load_report(args.after)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    d = diff.compare(before, after)
    print(diff.to_terminal(d, args.limit))
    for path, write, label in ((args.json, diff.to_json, "JSON"), (args.markdown, diff.to_markdown, "Markdown"), (args.html, diff.to_html, "HTML")):
        if path:
            Path(path).write_text(write(d), encoding="utf-8")
            print(f"{label} report: {path}")
    if args.fail_on != "none":
        limit = Severity.parse(args.fail_on)
        if any(f.severity >= limit for f in d.groups["new"]):
            return EXIT_FINDINGS
    # The second scan was incomplete: what disappeared cannot be called fixed.
    return EXIT_GAPS if d.after_gaps() else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # old Windows consoles cannot print every character
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return cmd_doctor()
    if args.command == "risk":
        return cmd_risk(args)
    if args.command == "diff":
        return cmd_diff(args)
    if args.command == "sbom":
        return cmd_sbom(args)
    if args.command == "history":
        return cmd_history(args)
    if args.command == "report":
        return cmd_report(args)
    if args.command == "ports":
        return cmd_ports(args)
    return cmd_dast(args) if args.command == "dast" else cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
