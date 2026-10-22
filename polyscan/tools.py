"""Wrappers around the external scanners.

Each tool knows how to build its command line and how to turn the tool's
JSON output into `Finding` objects. Parsing is kept in plain functions so it
can be tested with saved output, without running the scanners.
"""

from __future__ import annotations

import json
import os
import re
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

    def local_cmd(self, target: str, opts: "ScanOptions") -> list[str]:
        raise NotImplementedError

    def docker_cmd(self, opts: "ScanOptions") -> list[str]:
        """Arguments placed after the image name; the folder is at /src."""
        raise NotImplementedError

    def mounts(self, opts: "ScanOptions") -> list[tuple[str, str]]:
        """Extra read-only folders (host path, container path) needed in Docker."""
        return []

    def docker_flags(self, opts: "ScanOptions") -> list[str]:
        """Extra `docker run` options (before the image name)."""
        return []

    def prepare(self, workdir: Path, opts: "ScanOptions") -> None:
        """Write extra input files into the throw-away folder before the run."""

    def wanted(self, opts: "ScanOptions") -> bool:
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
        args = ["scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
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
AUTH_FILE = "zap-auth.properties"


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
        return ["--add-host", f"{HOST_FROM_CONTAINER}:host-gateway"]

    def docker_cmd(self, opts):
        if not opts.target_url:
            raise ValueError("no target URL")
        cmd = ["zap-baseline.py", "-t", opts.target_url, "-J", self.report_file, "-m", str(opts.zap_minutes)]
        if opts.auth_value:
            # Only the PATH of the settings file is on the command line; the secret is inside the file.
            cmd += ["-z", f"-configfile {self.workdir}/{AUTH_FILE}"]
        return cmd

    def prepare(self, workdir, opts):
        if opts.auth_value:
            path = Path(workdir) / AUTH_FILE
            path.write_text(zap_auth_properties(opts.auth_name, opts.auth_value), encoding="utf-8")
            path.chmod(0o644)  # the container's user must read it; the folder is private and deleted afterwards


def site_tools() -> list[Tool]:
    """Tools that scan a running site (used by `polyscan dast`)."""
    return [Zap()]


def all_tools() -> list[Tool]:
    return [Semgrep(), Gitleaks(), GitleaksHistory(), OsvScanner(), Bandit(), Checkov()]
