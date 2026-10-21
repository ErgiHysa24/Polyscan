"""Wrappers around the external scanners.

Each tool knows how to build its command line and how to turn the tool's
JSON output into `Finding` objects. Parsing is kept in plain functions so it
can be tested with saved output, without running the scanners.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .detect import EXTENSIONS
from .models import Finding, Severity

CONTAINER_ROOT = "/src"


def rel_path(path: str, root: str) -> str:
    """Make a path from tool output relative to the scanned folder."""
    p = path.replace("\\", "/")
    for prefix in (root.replace("\\", "/").rstrip("/") + "/", CONTAINER_ROOT + "/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return p[2:] if p.startswith("./") else p


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
        findings.append(
            Finding(
                tool="semgrep",
                severity=SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                rule=r.get("check_id", ""),
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
                message=r.get("Description", "Possible secret"),
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


def scan_errors(text: str) -> int:
    """Files Semgrep or Bandit could not analyze. Both exit successfully anyway,
    so the number is shown in the report instead of hiding behind "ok"."""
    data = json.loads(text)
    errors = data.get("errors", []) if isinstance(data, dict) else []
    return len(errors) if isinstance(errors, list) else 0


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

    def applies(self, detected: dict[str, int]) -> bool:
        if self.languages is None:
            return True
        return bool(self.languages & set(detected))

    def local_cmd(self, target: str, opts: "ScanOptions") -> list[str]:
        raise NotImplementedError

    def docker_cmd(self, opts: "ScanOptions") -> list[str]:
        """Arguments placed after the image name; the folder is at /src."""
        raise NotImplementedError


@dataclass
class ScanOptions:
    semgrep_configs: tuple[str, ...] = ("p/security-audit", "p/owasp-top-ten")
    excludes: tuple[str, ...] = ()


class Semgrep(Tool):
    def __init__(self):
        super().__init__(
            "semgrep",
            "semgrep",
            "semgrep/semgrep",
            parse_semgrep,
            languages=frozenset(EXTENSIONS.values()),
            reports_errors=True,
        )

    def _args(self, target: str, opts: ScanOptions) -> list[str]:
        args = ["scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for cfg in opts.semgrep_configs:
            args += ["--config", cfg]
        for ex in opts.excludes:
            args += ["--exclude", ex]
        return args + [target]

    def local_cmd(self, target, opts):
        return ["semgrep"] + self._args(target, opts)

    def docker_cmd(self, opts):
        return ["semgrep"] + self._args(CONTAINER_ROOT, opts)


class Gitleaks(Tool):
    def __init__(self):
        super().__init__(
            "gitleaks", "gitleaks", "zricethezav/gitleaks:latest", parse_gitleaks, ok_codes=(0,)
        )

    @staticmethod
    def _args(target: str) -> list[str]:
        # --exit-code 0: finding secrets is a result, not a failure of the tool.
        # --report-path - : write the JSON report to stdout.
        return [
            "dir", target, "--no-banner", "--redact", "--exit-code", "0",
            "--report-format", "json", "--report-path", "-",
        ]  # fmt: skip

    def local_cmd(self, target, opts):
        return ["gitleaks"] + self._args(target)

    def docker_cmd(self, opts):
        return self._args(CONTAINER_ROOT)


class OsvScanner(Tool):
    def __init__(self):
        super().__init__(
            "osv-scanner",
            "osv-scanner",
            "ghcr.io/google/osv-scanner:latest",
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


def all_tools() -> list[Tool]:
    return [Semgrep(), Gitleaks(), OsvScanner(), Bandit()]
