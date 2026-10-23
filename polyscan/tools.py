"""Wrappers around the external scanners.

Each tool knows how to build its command line and how to turn the tool's
JSON output into `Finding` objects. Parsing is kept in plain functions so it
can be tested with saved output, without running the scanners.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .detect import EXTENSIONS
from .models import Finding, Severity
from .target import HOST_FROM_CONTAINER

CONTAINER_ROOT = "/src"

# Docker images are pinned by DIGEST, not by tag. A tag such as `latest` can be
# moved by whoever controls the registry account (this is how the Trivy and KICS
# compromises reached their users); a digest is a hash of the image content, so
# a changed image simply fails to start. The version is kept next to it for
# humans and for `polyscan doctor`. To update: run the "show-latest-pins"
# workflow, read the new version and digest, review the release notes, change
# the line, and let the CI prove that the scanners still work.
IMAGES = {
    "semgrep": ("semgrep/semgrep", "1.181.1", "sha256:3db5c7af55eb1f512eac0abf0ab69a97b52c74b5e9a27314c221aee1a78d7ab2"),
    "gitleaks": ("zricethezav/gitleaks", "8.30.1", "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"),
    "osv-scanner": ("ghcr.io/google/osv-scanner", "2.7.0", "sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0"),
    "zap": ("ghcr.io/zaproxy/zaproxy", "2.17.0", "sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6"),
    "trivy": ("ghcr.io/aquasecurity/trivy", "0.76.1", "sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"),
    "checkov": ("bridgecrew/checkov", "3.3.30", "sha256:4b65e89f1fde292249fc0aa0d0db43302c036dfe39f7370b2d3517571082b894"),
}  # fmt: skip


def pinned_version(ref: str | None) -> str:
    """Human version of a pinned image reference, or "" if it is not one of ours."""
    for name, version, digest in IMAGES.values():
        if ref == f"{name}@{digest}":
            return version
    return ""


def image_ref(key: str) -> str:
    """The pinned reference to hand to `docker run`: name@sha256:..."""
    name, _version, digest = IMAGES[key]
    return f"{name}@{digest}"


def rel_path(path: str, root: str) -> str:
    """Make a path from tool output relative to the scanned folder."""
    p = path.replace("\\", "/")
    for prefix in (root.replace("\\", "/").rstrip("/") + "/", CONTAINER_ROOT + "/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return p.removeprefix("./")


def language_of(path: str) -> str:
    return EXTENSIONS.get(os.path.splitext(path)[1].lower(), "")


def _loads(text: str):
    """Parse tool output. Every supported tool prints JSON even when it finds
    nothing, so empty output means the tool did not really run (for example
    Docker failed with exit code 1, which some tools use for "findings")."""
    if not text.strip():
        raise ValueError("the tool printed nothing")
    return json.loads(text)


# ---------------------------------------------------------------- parsers


SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def parse_semgrep(text: str, root: str) -> list[Finding]:
    data = _loads(text) or {}
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        path = rel_path(r.get("path", ""), root)
        rule = r.get("check_id", "")
        if "polyscan-" in rule:
            # Semgrep prefixes the id with the folder of the rule file, which
            # differs between local runs and Docker. Show the stable part only.
            rule = rule[rule.index("polyscan-"):]
        findings.append(
            Finding(
                tool="semgrep",
                severity=SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                rule=rule,
                message=" ".join(str(extra.get("message", "")).split()),
                file=path,
                line=int(r.get("start", {}).get("line", 0)),
                category="code",
                language=language_of(path),
                # `lines` is "requires login" when the rules come from the registry
                # without an account, so it is not always real code.
                snippet=str(extra.get("lines", "")).strip(),
            )
        )
    return findings


def parse_gitleaks(text: str, root: str) -> list[Finding]:
    data = _loads(text) or []
    findings = []
    for r in data:
        path = rel_path(r.get("File", ""), root)
        findings.append(
            Finding(
                tool="gitleaks",
                severity=Severity.HIGH,
                rule=r.get("RuleID", ""),
                message=r.get("Description", "Possible secret")
                # Only in history scans. The short hash is enough to find the commit;
                # author and e-mail are personal data and stay out of reports.
                + (f" (in commit {str(r['Commit'])[:8]})" if r.get("Commit") else ""),
                file=path,
                line=int(r.get("StartLine", 0)),
                category="secret",
                language=language_of(path),
                # Never print the secret itself: the report may be shared.
                snippet="[secret redacted]",
            )
        )
    return findings


OSV_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _osv_severity(vuln: dict, group_scores: dict[str, float]) -> Severity:
    for vid in [vuln.get("id", "")] + list(vuln.get("aliases", [])):
        if vid in group_scores:
            return Severity.from_cvss(group_scores[vid])
    label = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    return OSV_LABELS.get(label, Severity.MEDIUM)


def parse_osv(text: str, root: str) -> list[Finding]:
    data = _loads(text) or {}
    findings = []
    for res in data.get("results", []):
        source = rel_path(res.get("source", {}).get("path", ""), root)
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            group_scores: dict[str, float] = {}
            for g in pkg.get("groups", []):
                try:
                    score = float(g.get("max_severity", ""))
                except (TypeError, ValueError):
                    continue
                for gid in g.get("ids", []):
                    group_scores[gid] = score
            for vuln in pkg.get("vulnerabilities", []):
                name = f'{info.get("name", "?")} {info.get("version", "?")}'
                summary = vuln.get("summary") or "Known vulnerability"
                findings.append(
                    Finding(
                        tool="osv-scanner",
                        severity=_osv_severity(vuln, group_scores),
                        rule=vuln.get("id", ""),
                        message=f"{name}: {summary}",
                        file=source,
                        line=0,
                        category="dependency",
                        language=info.get("ecosystem", "").split(":")[0].lower(),
                    )
                )
    return findings


BANDIT_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


# Bandit's "hardcoded password" checks quote the secret in the message and in
# the code excerpt. Reports get shared, so those two fields are replaced.
BANDIT_SECRET_TESTS = {"B105", "B106", "B107"}


def parse_bandit(text: str, root: str) -> list[Finding]:
    data = _loads(text) or {}
    findings = []
    for r in data.get("results", []):
        is_secret = r.get("test_id") in BANDIT_SECRET_TESTS
        findings.append(
            Finding(
                tool="bandit",
                severity=BANDIT_SEVERITY.get(str(r.get("issue_severity", "")).upper(), Severity.MEDIUM),
                rule=f'{r.get("test_id", "")} {r.get("test_name", "")}'.strip(),
                message="Possible hardcoded password (value hidden)" if is_secret else r.get("issue_text", ""),
                file=rel_path(r.get("filename", ""), root),
                line=int(r.get("line_number", 0)),
                category="secret" if is_secret else "code",
                language="python",
                snippet="[secret redacted]" if is_secret else str(r.get("code", "")).strip(),
            )
        )
    return findings


COMPOSER_SEVERITY = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}


def parse_composer_audit(text: str, root: str) -> list[Finding]:
    """The merged output of polyscan.auditrun for composer (one `composer audit --locked` per composer.lock).

    Composer lists advisories per package; a package that its author abandoned is listed too
    (`abandoned`: package -> suggested replacement or null). A package without a severity
    in the advisory is MEDIUM, never silently dropped."""
    data = _loads(text)
    if not isinstance(data, dict) or data.get("kind") != "composer":
        raise ValueError("this is not polyscan's composer audit output")
    findings, seen = [], set()
    for audit in data.get("audits") or []:
        path = _lock_path({**audit, "lockfile": audit.get("lockfile") or "composer.lock"})
        report = audit.get("report") or {}
        advisories = report.get("advisories") or {}
        for package, items in (advisories.items() if isinstance(advisories, dict) else []):
            for adv in items or []:
                rule = str(adv.get("cve") or adv.get("advisoryId") or "unknown-advisory")
                if (path, rule, package) in seen:
                    continue
                seen.add((path, rule, package))
                title = " ".join(str(adv.get("title") or "Known vulnerability").split())
                link = adv.get("link")
                findings.append(
                    Finding(
                        tool="composer-audit",
                        severity=COMPOSER_SEVERITY.get(str(adv.get("severity")).lower(), Severity.MEDIUM),
                        rule=rule,
                        message=f"{package} ({adv.get('affectedVersions', 'versions unknown')}): {title}."
                        + (f" {link}" if link else ""),
                        file=path,
                        line=0,
                        category="dependency",
                        language="php",
                    )
                )
        abandoned = report.get("abandoned") or {}
        for package, replacement in (abandoned.items() if isinstance(abandoned, dict) else []):
            hint = f"use {replacement} instead" if replacement else "no replacement is suggested"
            findings.append(
                Finding("composer-audit", Severity.LOW, "abandoned-package", f"{package} is abandoned: {hint}.",
                        path, 0, "dependency", "php")  # fmt: skip
            )
    return findings


# Weaknesses where attacker-controlled input reaches something dangerous: at least HIGH.
INJECTION_CWES = {"22", "78", "89", "94", "95", "98", "502", "611", "918"}


def parse_progpilot(text: str, root: str) -> list[Finding]:
    """polyscan.sastrun's output for Progpilot: its taint findings plus the files it could not parse.

    Progpilot says WHERE untrusted data comes from (source) and where it ends up (sink), which is
    the useful part of the message. A file that does not parse is reported as INFO, because
    Progpilot itself would have skipped it without a word."""
    data = _loads(text)
    if not isinstance(data, dict) or data.get("kind") != "progpilot":
        raise ValueError("this is not polyscan's progpilot output")
    findings = []
    for r in data.get("results") or []:
        cwe = str(r.get("vuln_cwe", "")).replace("CWE_", "")
        src = r.get("source_name")
        src = ", ".join(str(x) for x in src) if isinstance(src, list) else str(src or "user input")
        line = r.get("sink_line", 0)
        findings.append(
            Finding(
                tool="progpilot",
                severity=Severity.HIGH if cwe in INJECTION_CWES else Severity.MEDIUM,
                rule=str(r.get("vuln_name", "taint")).strip(),
                message=f"Untrusted data ({src}) reaches {r.get('sink_name', 'a dangerous function')}"
                + (f" (CWE-{cwe})" if cwe.isdigit() else ""),
                file=rel_path(str(r.get("sink_file", "")), root),
                line=int(line) if isinstance(line, int) or str(line).isdigit() else 0,
                category="code",
                language="php",
            )
        )
    for name in data.get("unparsed") or []:
        findings.append(
            Finding("progpilot", Severity.INFO, "not-analyzed",
                    "Progpilot could not analyze this file (PHP syntax error or unreadable): it was NOT checked.",
                    str(name), 0, "code", "php")  # fmt: skip
        )
    return findings


def _java_source(root: str, sourcepath: str, cache: dict) -> str:
    """The project file that a compiled class came from: SpotBugs only knows 'com/x/App.java'."""
    if "index" not in cache:
        index: dict[str, list[str]] = {}
        base = Path(root)
        for here, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for name in files:
                if name.endswith(".java"):
                    index.setdefault(name, []).append((Path(here) / name).relative_to(base).as_posix())
        cache["index"] = index
    wanted = sourcepath.replace("\\", "/")
    for candidate in sorted(cache["index"].get(wanted.rsplit("/", 1)[-1], [])):
        if candidate == wanted or candidate.endswith("/" + wanted):
            return candidate
    return wanted


def parse_spotbugs(text: str, root: str) -> list[Finding]:
    """SpotBugs XML with the Find Security Bugs plugin. Only the SECURITY category is kept:
    the rest are general code-quality bugs (resource leaks, style), not what a security scan is for.

    Severity: SpotBugs' own priority (1 high, 2 medium, 3 low); injection weaknesses are raised to HIGH."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:  # SpotBugs never writes these; refuse entity tricks
        raise ValueError("unexpected DOCTYPE in SpotBugs output")
    tree = ET.fromstring(text)
    if tree.tag != "BugCollection":
        raise ValueError("this is not a SpotBugs report")
    findings, cache = [], {}
    for bug in tree.findall("BugInstance"):
        if bug.get("category") != "SECURITY":
            continue
        priority = bug.get("priority", "2")
        cwe = bug.get("cweid", "")
        severity = {"1": Severity.HIGH, "2": Severity.MEDIUM}.get(priority, Severity.LOW)
        if cwe in INJECTION_CWES:
            severity = max(severity, Severity.HIGH)
        line_el = bug.find("SourceLine[@primary='true']")
        if line_el is None:
            line_el = bug.find(".//SourceLine")
        sourcepath = (line_el.get("sourcepath") if line_el is not None else "") or ""
        start = (line_el.get("start") if line_el is not None else "0") or "0"
        short = " ".join((bug.findtext("ShortMessage") or "").split())
        long = " ".join((bug.findtext("LongMessage") or short).split())
        findings.append(
            Finding(
                tool="spotbugs",
                severity=severity,
                rule=bug.get("type", "unknown"),
                message=f"{short}" + (f" (CWE-{cwe})" if cwe.isdigit() else "") + f": {long}",
                file=_java_source(root, sourcepath, cache) if sourcepath else "",
                line=int(start) if start.isdigit() else 0,
                category="code",
                language="java",
            )
        )
    return findings


ZAP_RISK = {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH}


def parse_zap(text: str, root: str) -> list[Finding]:
    """ZAP's JSON report: sites -> alerts -> instances (one per URL).

    One finding is made per ALERT, pointing at the first URL, with the number of
    URLs in the message: "CSP header not set" on 40 pages is one lesson, not 40.
    `root` is the URL the person gave. Inside Docker, ZAP saw the host machine
    as host.docker.internal, so that name is changed back."""
    data = _loads(text)
    if not isinstance(data, dict) or data.get("@programName") != "ZAP":
        raise ValueError("this is not a ZAP report")
    original = urlsplit(root).hostname or ""
    if ":" in original:
        original = f"[{original}]"  # IPv6 literal
    findings = []
    for site in data.get("site") or []:
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or []
            uri = str((instances[0] if instances else {}).get("uri") or site.get("@name", ""))
            if original:
                uri = uri.replace(f"//{HOST_FROM_CONTAINER}", f"//{original}", 1)
            count = int(alert.get("count") or len(instances) or 1)
            name = " ".join(str(alert.get("name") or alert.get("alert") or "ZAP alert").split())
            findings.append(
                Finding(
                    tool="zap",
                    severity=ZAP_RISK.get(str(alert.get("riskcode")), Severity.MEDIUM),
                    rule=str(alert.get("alertRef") or alert.get("pluginid") or ""),
                    message=name + (f" ({count} URLs)" if count > 1 else ""),
                    file=uri[:300],
                    line=0,
                    category="runtime",
                )
            )
    return findings


NPM_SEVERITY = {"info": Severity.INFO, "low": Severity.LOW, "moderate": Severity.MEDIUM,
                "high": Severity.HIGH, "critical": Severity.CRITICAL}  # fmt: skip


def _lock_path(audit: dict) -> str:
    folder = str(audit.get("dir") or ".").replace("\\", "/").strip("/")
    name = str(audit.get("lockfile") or "package-lock.json")
    return name if folder in ("", ".") else f"{folder}/{name}"


def parse_npm_audit(text: str, root: str) -> list[Finding]:
    """The merged output of polyscan.auditrun for npm (one `npm audit --json` per lockfile).

    In npm's report each package lists WHY it is affected ("via"): either an advisory
    (a dict) or just the name of another package (a string, the advisory is listed under
    that one). Only the dicts are findings, so a problem in `body-parser` that also makes
    `express` vulnerable is counted once."""
    data = _loads(text)
    if not isinstance(data, dict) or data.get("kind") != "npm":
        raise ValueError("this is not polyscan's npm audit output")
    findings, seen = [], set()
    for audit in data.get("audits") or []:
        path = _lock_path(audit)
        packages = (audit.get("report") or {}).get("vulnerabilities") or {}
        for name, pkg in packages.items():
            fix = pkg.get("fixAvailable")
            if isinstance(fix, dict):
                hint = f" Fix: update {fix.get('name', name)} to {fix.get('version', '?')}" + (
                    " (breaking change)." if fix.get("isSemVerMajor") else "."
                )
            else:
                hint = " Fix available." if fix else " No fix published yet."
            for via in pkg.get("via") or []:
                if not isinstance(via, dict):
                    continue
                url = str(via.get("url") or "")
                rule = url.rstrip("/").rsplit("/", 1)[-1] if "/advisories/" in url else str(via.get("source", ""))
                if (path, rule, via.get("name")) in seen:
                    continue
                seen.add((path, rule, via.get("name")))
                title = " ".join(str(via.get("title") or "Known vulnerability").split())
                findings.append(
                    Finding(
                        tool="npm-audit",
                        severity=NPM_SEVERITY.get(str(via.get("severity")), Severity.MEDIUM),
                        rule=rule,
                        message=f"{via.get('name', name)} ({via.get('range', 'versions unknown')}): {title}.{hint}",
                        file=path,
                        line=0,
                        category="dependency",
                        language="javascript",
                    )
                )
    return findings


CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}  # fmt: skip


def cvss3_score(vector: str) -> float | None:
    """Base score (0-10) of a CVSS v3.0/v3.1 vector such as 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'.

    RustSec gives only the vector, not the number, so the number is computed with the
    formula from the CVSS specification. Anything that is not a complete v3 vector gives None."""
    try:
        head, *parts = vector.split("/")
        if head not in ("CVSS:3.0", "CVSS:3.1"):
            return None
        m = dict(part.split(":", 1) for part in parts)
        changed = {"U": False, "C": True}[m["S"]]
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        w = CVSS3_WEIGHTS
        iss = 1 - (1 - w["C"][m["C"]]) * (1 - w["I"][m["I"]]) * (1 - w["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * w["AV"][m["AV"]] * w["AC"][m["AC"]] * privileges * w["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = min((1.08 if changed else 1.0) * (impact + exploit), 10)
    return math.ceil(round(raw * 100000) / 10000) / 10  # "round up" to one decimal, as the spec defines it


def severity_from_score(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM  # no usable score: neither alarm nor dismissal
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


# RustSec warnings are not exploitable bugs in the usual sense, but a crate nobody maintains
# or a release that was withdrawn is something to know about.
CARGO_WARNING_SEVERITY = {"unsound": Severity.MEDIUM, "unmaintained": Severity.LOW, "yanked": Severity.LOW}


def parse_cargo_audit(text: str, root: str) -> list[Finding]:
    """The merged output of polyscan.auditrun for cargo (one `cargo audit --json` per Cargo.lock)."""
    data = _loads(text)
    if not isinstance(data, dict) or data.get("kind") != "cargo":
        raise ValueError("this is not polyscan's cargo audit output")
    findings = []
    for audit in data.get("audits") or []:
        path = _lock_path(audit)
        report = audit.get("report") or {}
        for item in (report.get("vulnerabilities") or {}).get("list") or []:
            adv, pkg = item.get("advisory") or {}, item.get("package") or {}
            patched = (item.get("versions") or {}).get("patched") or []
            fix = f" Fixed in: {', '.join(map(str, patched))}." if patched else " No patched version yet."
            findings.append(
                Finding(
                    tool="cargo-audit",
                    severity=severity_from_score(cvss3_score(str(adv.get("cvss") or ""))),
                    rule=str(adv.get("id", "")),
                    message=f"{pkg.get('name', '?')} {pkg.get('version', '?')}: "
                            f"{' '.join(str(adv.get('title') or 'Known vulnerability').split())}.{fix}",
                    file=path, line=0, category="dependency", language="rust",
                )
            )  # fmt: skip
        # "warnings" is {kind: [ {kind, package, advisory-or-null}, ... ]}
        for kind, entries in (report.get("warnings") or {}).items():
            for entry in entries or []:
                adv, pkg = entry.get("advisory") or {}, entry.get("package") or {}
                findings.append(
                    Finding(
                        tool="cargo-audit",
                        severity=CARGO_WARNING_SEVERITY.get(str(kind), Severity.LOW),
                        rule=str(adv.get("id") or kind),
                        message=f"{pkg.get('name', '?')} {pkg.get('version', '?')} ({kind}): "
                                f"{' '.join(str(adv.get('title') or kind).split())}.",
                        file=path, line=0, category="dependency", language="rust",
                    )
                )  # fmt: skip
    return findings


TRIVY_SEVERITY = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
                  "LOW": Severity.LOW, "UNKNOWN": Severity.LOW}  # fmt: skip


def parse_trivy(text: str, root: str) -> list[Finding]:
    """The merged output of polyscan.imagescan (one Trivy report per image).

    Each finding points at the file and line that NAME the image (the FROM or image: line), because
    that is where a person acts: change the tag or the base image. The same vulnerability seen in
    several layers of an image is reported once."""
    data = _loads(text)
    if not isinstance(data, dict) or data.get("kind") != "trivy":
        raise ValueError("this is not polyscan's image scan output")
    findings, seen = [], set()
    for image in data.get("images") or []:
        ref, source, line = str(image.get("ref", "?")), str(image.get("source", "")), int(image.get("line") or 0)
        for result in (image.get("report") or {}).get("Results") or []:
            for v in result.get("Vulnerabilities") or []:
                key = (ref, v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
                if key in seen:
                    continue
                seen.add(key)
                fixed = v.get("FixedVersion")
                fix = f" Fixed in: {fixed}." if fixed else " No fix published yet."
                title = " ".join(str(v.get("Title") or v.get("VulnerabilityID") or "Known vulnerability").split())
                findings.append(
                    Finding(
                        tool="trivy",
                        severity=TRIVY_SEVERITY.get(str(v.get("Severity")), Severity.MEDIUM),
                        rule=str(v.get("VulnerabilityID", "")),
                        message=f"{ref}: {v.get('PkgName', '?')} {v.get('InstalledVersion', '?')}: {title}.{fix}",
                        file=source, line=line, category="dependency",
                    )
                )  # fmt: skip
    # A reference with a variable (FROM ${BASE}) cannot be resolved without building: say so instead of
    # silently leaving it out, because an image nobody checked must not look like a clean one.
    for item in data.get("skipped") or []:
        findings.append(
            Finding(
                tool="trivy", severity=Severity.INFO, rule="polyscan-image-not-scanned",
                message=f"Image reference {item.get('ref', '?')} contains a variable, so it was NOT scanned. "
                        "Use a fixed image name here or scan the built image yourself.",
                file=str(item.get("source", "")), line=int(item.get("line") or 0), category="config",
            )
        )  # fmt: skip
    return findings


CHECKOV_KINDS = {"dockerfile": "docker", "kubernetes": "kubernetes", "terraform": "terraform"}


def parse_checkov(text: str, root: str) -> list[Finding]:
    """Checkov prints ONE object when it found a single kind of file, a LIST of
    objects when it found several, and only a summary on a folder with nothing
    to check. All three shapes are handled here."""
    data = _loads(text)
    reports = data if isinstance(data, list) else [data]
    findings = []
    for report in reports:
        kind = str(report.get("check_type", ""))
        for r in (report.get("results") or {}).get("failed_checks", []):
            # With an absolute folder, file_path is relative to it, with a leading "/".
            path = str(r.get("file_path", "")).replace("\\", "/").lstrip("/")
            lines = r.get("file_line_range") or [0]
            findings.append(
                Finding(
                    tool="checkov",
                    # The free version gives no severity (null): start at medium.
                    severity=BANDIT_SEVERITY.get(str(r.get("severity") or "").upper(), Severity.MEDIUM),
                    rule=r.get("check_id", ""),
                    message=r.get("check_name", ""),
                    file=path,
                    line=int(lines[0]),
                    category="config",
                    language=CHECKOV_KINDS.get(kind, kind),
                )
            )
    return findings


def scan_errors(text: str) -> int:
    """Files a tool could not analyze, although it exited successfully. Semgrep and
    Bandit list them under "errors"; Checkov counts them in summary.parsing_errors.
    The number is shown in the report instead of hiding behind "ok"."""
    data = json.loads(text)
    total = 0
    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict):
            continue
        errors = item.get("errors", [])
        total += len(errors) if isinstance(errors, list) else 0
        summary = item.get("summary", item)  # an empty folder prints the summary alone
        count = summary.get("parsing_errors", 0) if isinstance(summary, dict) else 0
        total += count if isinstance(count, int) else 0
    return total


# ------------------------------------------------------------------ tools


@dataclass
class Tool:
    name: str
    binary: str
    image: str | None  # Docker image, or None if the tool cannot run in Docker
    parse: callable
    ok_codes: tuple[int, ...] = (0, 1)
    skip_codes: dict[int, str] = field(default_factory=dict)
    languages: frozenset[str] | None = None  # None = any language
    reports_errors: bool = False  # output has an "errors" list worth surfacing
    uses_folder: bool = True  # False for tools that scan a URL, not a folder
    local_ok: bool = True  # False for tools that only run in Docker
    report_file: str | None = None  # tool writes its JSON to this file instead of stdout
    workdir: str = "/zap/wrk"  # where that file lives inside the container (rw)

    def applies(self, detected: dict[str, int]) -> bool:
        if self.languages is None:
            return True
        return bool(self.languages & set(detected))

    def local_cmd(self, target: str, opts: ScanOptions) -> list[str]:
        raise NotImplementedError

    def docker_cmd(self, opts: ScanOptions) -> list[str]:
        """Arguments placed after the image name; the folder is at /src."""
        raise NotImplementedError

    def mounts(self, opts: ScanOptions) -> list[tuple[str, str]]:
        """Extra read-only folders (host path, container path) needed in Docker."""
        return []

    def docker_flags(self, opts: ScanOptions) -> list[str]:
        """Extra `docker run` options (before the image name)."""
        return []

    def stdin_text(self, opts: ScanOptions) -> str | None:
        """Text sent to the program's standard input (used for secrets: never a file, never an argument)."""
        return None

    def wanted(self, opts: ScanOptions) -> bool:
        """False for tools that run only when asked for (silently left out otherwise)."""
        return True

    def precheck(self, root: Path) -> str | None:
        """A reason why the tool cannot do its job on this folder, or None."""
        return None


RULES_DIR = Path(__file__).parent / "rules"
RULES_IN_CONTAINER = "/rules"
BUILTIN_RULE_FILES = ("sql-injection.yml", "docker-compose.yml", "dockerfile.yml")


@dataclass
class ScanOptions:
    semgrep_configs: tuple[str, ...] = ("p/security-audit", "p/owasp-top-ten")
    excludes: tuple[str, ...] = ()
    builtin_rules: bool = True  # polyscan's own rules (SQL, Compose, Dockerfile)
    history: bool = False  # also look for secrets in old commits
    target_url: str = ""  # live-site scans: the URL as the tool will see it
    zap_minutes: int = 1  # live-site scans: minutes the spider may run
    auth_name: str = ""  # live-site scans: header added to every request (Authorization, Cookie...)
    auth_value: str = field(default="", repr=False)  # its value: a SECRET, so never in repr() or logs


class Semgrep(Tool):
    def __init__(self):
        super().__init__(
            "semgrep",
            "semgrep",
            image_ref("semgrep"),
            parse_semgrep,
            languages=frozenset(EXTENSIONS.values()) | {"docker"},  # "docker": the Compose rules
            reports_errors=True,
        )

    def _args(self, target: str, opts: ScanOptions, rules_dir: str) -> list[str]:
        # No --quiet: with it a failure (for example no internet to download the rule packs) prints NOTHING,
        # and the report would say "exit code 2" without a reason. JSON still goes alone to stdout.
        args = ["scan", "--json", "--metrics=off", "--disable-version-check"]
        for cfg in opts.semgrep_configs:
            args += ["--config", cfg]
        if opts.builtin_rules:
            for name in BUILTIN_RULE_FILES:
                args += ["--config", f"{rules_dir}/{name}"]
        for ex in opts.excludes:
            args += ["--exclude", ex]
        return args + [target]

    def local_cmd(self, target, opts):
        return ["semgrep"] + self._args(target, opts, str(RULES_DIR))

    def docker_cmd(self, opts):
        return ["semgrep"] + self._args(CONTAINER_ROOT, opts, RULES_IN_CONTAINER)

    def mounts(self, opts):
        return [(str(RULES_DIR), RULES_IN_CONTAINER)] if opts.builtin_rules else []


class Gitleaks(Tool):
    """Secrets in the files as they are now (a deleted file is not seen)."""

    COMMAND = "dir"

    def __init__(self, name: str = "gitleaks"):
        super().__init__(
            name, "gitleaks", image_ref("gitleaks"), parse_gitleaks, ok_codes=(0,)
        )  # fmt: skip

    def _args(self, target: str) -> list[str]:
        # --exit-code 0: finding secrets is a result, not a failure of the tool.
        # --report-path - : write the JSON report to stdout.
        return [
            self.COMMAND, target, "--no-banner", "--redact", "--exit-code", "0",
            "--report-format", "json", "--report-path", "-",
        ]  # fmt: skip

    def local_cmd(self, target, opts):
        return ["gitleaks"] + self._args(target)

    def docker_cmd(self, opts):
        return self._args(CONTAINER_ROOT)


class GitleaksHistory(Gitleaks):
    """Secrets in every commit, including files deleted long ago.

    A key removed in a later commit is still readable by anyone who can read the
    repository, so it must be treated as leaked and replaced."""

    COMMAND = "git"

    def __init__(self):
        super().__init__("gitleaks-history")

    def wanted(self, opts):
        return opts.history

    def precheck(self, root):
        if not (root / ".git").exists():
            return "no .git folder here: run it from the root of the repository"
        if (root / ".git" / "shallow").exists():
            return "shallow clone, old commits are missing: run `git fetch --unshallow` (in GitHub Actions: fetch-depth: 0)"
        return None


class OsvScanner(Tool):
    def __init__(self):
        super().__init__(
            "osv-scanner",
            "osv-scanner",
            image_ref("osv-scanner"),
            parse_osv,
            skip_codes={128: "no dependency files (lockfiles) found"},
        )

    @staticmethod
    def _args(target: str) -> list[str]:
        return ["scan", "source", "-r", "--format", "json", target]

    def local_cmd(self, target, opts):
        return ["osv-scanner"] + self._args(target)

    def docker_cmd(self, opts):
        return self._args(CONTAINER_ROOT)


class Bandit(Tool):
    def __init__(self):
        super().__init__(
            "bandit", "bandit", None, parse_bandit, languages=frozenset({"python"}), reports_errors=True
        )

    def local_cmd(self, target, opts):
        cmd = ["bandit", "-r", target, "-f", "json", "-q"]
        if opts.excludes:
            cmd += ["-x", ",".join(opts.excludes)]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("bandit has no official Docker image")


class NpmAudit(Tool):
    """`npm audit` on every package-lock.json. Needs npm and the internet (npm's advisory service).

    It reads the lockfile only: nothing is installed and no project script runs."""

    def __init__(self):
        super().__init__(
            "npm-audit", "npm", None, parse_npm_audit,
            ok_codes=(0,), skip_codes={4: "no package-lock.json found"}, languages=frozenset({"javascript"}),
        )  # fmt: skip

    def local_cmd(self, target, opts):
        cmd = [sys.executable, "-m", "polyscan.auditrun", "npm", target]
        for pattern in opts.excludes:
            cmd += ["--exclude", pattern]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("npm audit has no Docker image here")


class CargoAudit(Tool):
    """`cargo-audit` on every Cargo.lock, against the RustSec advisory database.

    Needs the cargo-audit program (`cargo install cargo-audit --locked`) and the internet
    (it downloads the advisory database from GitHub). It reads the lockfile only."""

    def __init__(self):
        super().__init__(
            "cargo-audit", "cargo-audit", None, parse_cargo_audit,
            ok_codes=(0,), skip_codes={4: "no Cargo.lock found"}, languages=frozenset({"rust"}),
        )  # fmt: skip

    def local_cmd(self, target, opts):
        cmd = [sys.executable, "-m", "polyscan.auditrun", "cargo", target]
        for pattern in opts.excludes:
            cmd += ["--exclude", pattern]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("cargo audit has no Docker image here")


class ComposerAudit(Tool):
    """`composer audit --locked` on every composer.lock (PHP). Needs composer and the internet (Packagist's
    advisory database). It reads the lockfile only: nothing is installed and no project script runs."""

    def __init__(self):
        super().__init__(
            "composer-audit", "composer", None, parse_composer_audit,
            ok_codes=(0,), skip_codes={4: "no composer.lock found"}, languages=frozenset({"php"}),
        )  # fmt: skip

    def local_cmd(self, target, opts):
        cmd = [sys.executable, "-m", "polyscan.auditrun", "composer", target]
        for pattern in opts.excludes:
            cmd += ["--exclude", pattern]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("composer audit has no Docker image here")


class Progpilot(Tool):
    """Taint analysis of PHP source (untrusted data -> dangerous function): SQL injection, XSS, command injection...

    Needs the `progpilot` command (a launcher for progpilot.phar) and php. Every file is checked with
    `php -l` first, because Progpilot stays silent on files it cannot read."""

    def __init__(self):
        super().__init__(
            "progpilot", "progpilot", None, parse_progpilot,
            ok_codes=(0,), skip_codes={4: "no PHP files found"}, languages=frozenset({"php"}),
        )  # fmt: skip

    def local_cmd(self, target, opts):
        cmd = [sys.executable, "-m", "polyscan.sastrun", "progpilot", target]
        for pattern in opts.excludes:
            cmd += ["--exclude", pattern]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("progpilot has no official Docker image")


class SpotBugs(Tool):
    """SpotBugs with the Find Security Bugs plugin on COMPILED Java classes (Maven target/classes, Gradle build/classes).

    SpotBugs reads bytecode, so the project must be built first; without compiled classes the tool
    is reported as skipped, with the reason, never as clean."""

    def __init__(self):
        super().__init__(
            "spotbugs", "spotbugs", None, parse_spotbugs,
            ok_codes=(0,), skip_codes={4: "no compiled classes found: build the project first (mvn compile / gradle classes)"},
            languages=frozenset({"java"}),
        )  # fmt: skip

    def local_cmd(self, target, opts):
        cmd = [sys.executable, "-m", "polyscan.sastrun", "spotbugs", target]
        for pattern in opts.excludes:
            cmd += ["--exclude", pattern]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("spotbugs has no official Docker image")


class Trivy(Tool):
    """Known vulnerabilities in the Docker images a project uses (the operating system and packages inside).

    Reads image names from Dockerfiles (FROM) and Compose files (image:), then runs the pinned Trivy
    image once per name. Needs Docker and the internet (the registry and Trivy's database); the
    project folder is never given to Trivy. Only HIGH and CRITICAL are reported."""

    def __init__(self):
        super().__init__(
            "trivy", "docker", None, parse_trivy,
            ok_codes=(0,), skip_codes={4: "no Docker image references found"}, languages=frozenset({"docker"}),
        )  # fmt: skip

    def local_cmd(self, target, opts):
        cmd = [sys.executable, "-m", "polyscan.imagescan", target]
        for pattern in opts.excludes:
            cmd += ["--exclude", pattern]
        return cmd

    def docker_cmd(self, opts):
        raise NotImplementedError("trivy is started by polyscan.imagescan, which needs the docker program")


class Checkov(Tool):
    """Misconfiguration in Dockerfiles, Kubernetes, Terraform and CI workflows.

    Runs only when the project has such files (see detect.CONFIG_NAMES)."""

    FRAMEWORKS = ("dockerfile", "kubernetes", "terraform", "helm", "github_actions")

    def __init__(self):
        super().__init__(
            "checkov", "checkov", image_ref("checkov"), parse_checkov,
            languages=frozenset({"docker", "terraform"}), reports_errors=True,
        )  # fmt: skip

    def _args(self, target: str) -> list[str]:
        # --framework: only configuration checks. Secrets are Gitleaks' job, so
        # leaving the default (all frameworks) would report them twice.
        # --skip-download: no calls to the vendor's platform.
        # exit code 1 only means "some check failed", like Semgrep.
        return ["-d", target, "-o", "json", "--quiet", "--skip-download", "--framework", *self.FRAMEWORKS]

    def local_cmd(self, target, opts):
        return ["checkov"] + self._args(target)

    def docker_cmd(self, opts):
        return self._args(CONTAINER_ROOT)


AUTH_NAME_OK = re.compile(r"[A-Za-z0-9-]{1,64}")
# Deliberately narrow: enough for "Bearer <token>", JWTs and "name=value; name2=value2" cookies.
# Characters with a special meaning in the ZAP settings file (comma, backslash, quotes, #, newline)
# are refused instead of escaped: a rule I cannot be sure of is a rule that may leak or break.
AUTH_VALUE_OK = re.compile(r"[A-Za-z0-9._~+/=:; -]{1,4096}")
AUTH_PATH = "/tmp/zap-auth.properties"  # inside the container only


def check_auth(name: str, value: str) -> None:
    """Raise ValueError (without ever repeating the value) if the header cannot be used safely."""
    if not AUTH_NAME_OK.fullmatch(name):
        raise ValueError("the header name may contain only letters, digits and '-' (max 64)")
    if not AUTH_VALUE_OK.fullmatch(value):
        raise ValueError(
            "the header value is empty, longer than 4096 characters, or contains a character that is "
            "not allowed (allowed: letters, digits and . _ ~ + / = : ; space and -)"
        )


def zap_auth_properties(name: str, value: str) -> str:
    """ZAP settings that add one header to every request (the 'replacer' add-on)."""
    check_auth(name, value)
    return "\n".join([
        "replacer.full_list(0).description=polyscan-auth",
        "replacer.full_list(0).enabled=true",
        "replacer.full_list(0).matchtype=REQ_HEADER",
        f"replacer.full_list(0).matchstr={name}",
        "replacer.full_list(0).regex=false",
        f"replacer.full_list(0).replacement={value}",
        "",
    ])  # fmt: skip


class Zap(Tool):
    """OWASP ZAP baseline: browses a running site and checks what it answers.

    It is passive: it sends ordinary requests (a spider following links) and
    analyses the responses; it does not attack. Docker only, because ZAP is a large
    Java program. The report goes to a file in a throw-away writable folder.
    ZAP exits 0 (nothing), 1 (a rule set to FAIL) or 2 (warnings); 3 is a failure,
    for example when the site does not answer."""

    def __init__(self):
        super().__init__(
            "zap", "zap-baseline.py", image_ref("zap"), parse_zap,
            ok_codes=(0, 1, 2), uses_folder=False, local_ok=False, report_file="zap-report.json",
        )  # fmt: skip

    def local_cmd(self, target, opts):
        raise NotImplementedError("ZAP runs only in Docker")

    def docker_flags(self, opts):
        # Lets the container reach a server on this computer (localhost inside a container is the container).
        flags = ["--add-host", f"{HOST_FROM_CONTAINER}:host-gateway"]
        if opts.auth_value:
            flags.append("-i")  # keep stdin open: the login header arrives there
        return flags

    def docker_cmd(self, opts):
        if not opts.target_url:
            raise ValueError("no target URL")
        cmd = ["zap-baseline.py", "-t", opts.target_url, "-J", self.report_file, "-m", str(opts.zap_minutes)]
        if not opts.auth_value:
            return cmd
        # The secret reaches the container through STANDARD INPUT and is written to a file that exists only
        # inside the container (readable by its user alone, gone with --rm). So it is never an argument
        # (visible in `ps`) and never a file on this computer (readable by other users of a shared machine).
        # umask only inside the parentheses: the report ZAP writes later must stay readable by this computer's user.
        script = f'(umask 077; cat > {AUTH_PATH}) && exec "$@"'
        return ["sh", "-c", script, "sh", *cmd, "-z", f"-configfile {AUTH_PATH}"]

    def stdin_text(self, opts):
        return zap_auth_properties(opts.auth_name, opts.auth_value) if opts.auth_value else None


def site_tools() -> list[Tool]:
    """Tools that scan a running site (used by `polyscan dast`)."""
    return [Zap()]


def all_tools() -> list[Tool]:
    return [Semgrep(), Gitleaks(), GitleaksHistory(), OsvScanner(), Bandit(), NpmAudit(), CargoAudit(), ComposerAudit(), Progpilot(), SpotBugs(), Trivy(), Checkov()]
