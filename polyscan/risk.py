"""Risk assessment: turns scanner findings into a risk register.

A scanner says "this line is dangerous". A risk assessment answers a different question:
"how much does it matter FOR THIS APPLICATION, and what do I do first?". The classic way is a
5x5 matrix:

    risk score = likelihood (1-5) x impact (1-5)          ->  1..25

Everything here is a transparent HEURISTIC, not a measurement. Each risk carries the list of
reasons that produced its two numbers, so a person can disagree with a step and see which one.

  likelihood  how easy it is for someone to use the weakness
              starts from the KIND of finding (a leaked secret is easier to use than a
              missing configuration hardening) and moves with how exposed the app is
  impact      how bad it is when it is used
              starts from the tool's severity and moves with how sensitive the data is

Levels: 1-5 low, 6-12 medium, 13-19 high, 20-25 critical (a common convention for 5x5 matrices).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import ERROR, UNAVAILABLE, Finding, Severity

MAX_REPORT_BYTES = 50 * 1024 * 1024

# ---------------------------------------------------------------- the scales

EXPOSURES = {
    "internet": (+1, "the application is reachable from the internet"),
    "internal": (0, "the application is reachable only inside a private network"),
    "local": (-1, "the application runs only on one machine"),
}
DATA = {
    "public": (-1, "the application holds only public data"),
    "internal": (0, "the application holds internal business data"),
    "personal": (+1, "the application holds personal or financial data (users, passwords, payments)"),
}
KIND_LIKELIHOOD = {
    "secret": (4, "a leaked secret can be used by anyone who can read it, with no skill needed"),
    "runtime": (3, "seen on the running site, so any visitor can observe it"),
    "dependency": (3, "a published advisory for a library in use, so the weakness is publicly documented"),
    "code": (3, "a risky pattern in the code; exploitation depends on how the data reaches it"),
    "config": (2, "a hardening gap; usually needs another weakness to be exploited"),
}
SEVERITY_IMPACT = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1,
}  # fmt: skip
LEVELS = ["low", "medium", "high", "critical"]
LEVEL_UPPER = {"low": 5, "medium": 12, "high": 19, "critical": 25}  # score <= bound
TARGETS = {  # a common convention, offered as a suggestion: adjust it to your own policy
    "critical": "immediately (within 24 hours)",
    "high": "within 7 days",
    "medium": "within 30 days",
    "low": "in the next planned release",
}


def level_for(score: int) -> str:
    for name in LEVELS:
        if score <= LEVEL_UPPER[name]:
            return name
    return "critical"


def clamp(value: int) -> int:
    return max(1, min(5, value))


# ---------------------------------------------------------------- mitigations

# (pattern on "rule message", advice). First match wins; order goes from specific to general.
ADVICE = [
    (r"sql", "Use parameterized queries (placeholders) or the ORM's safe API. Never build SQL by joining text with user input."),
    (r"xss|cross.site scripting|innerhtml|document\.write", "Escape output for its context, keep the template engine's auto-escaping on, and add a Content-Security-Policy."),
    (r"command injection|os\.system|subprocess|shell=true|exec\(|child_process|with a shell", "Do not build commands from text: pass an argument list without a shell and check inputs against an allow-list."),
    (r"deserial|pickle|yaml\.load|unserialize|objectinputstream", "Never deserialize data from users. Use a plain format such as JSON, or a safe loader."),
    (r"path traversal|directory traversal|\.\./|send_file|open\(", "Resolve the final path and check it stays inside the allowed folder; do not use user input as a file name."),
    (r"md5|sha1|weak hash|weak crypto|des\b|ecb", "Use modern primitives: argon2 or bcrypt for passwords, SHA-256 or better for integrity, AES-GCM for encryption."),
    (r"csrf", "Add anti-CSRF tokens to state-changing forms and set cookies with SameSite=Lax or Strict."),
    (r"content security policy|\bcsp\b", "Send a Content-Security-Policy header that allows only the sources the site needs."),
    (r"httponly|samesite|secure flag|cookie", "Set HttpOnly, Secure and SameSite on session cookies."),
    (r"clickjack|x-frame-options|frame-ancestors", "Send X-Frame-Options: DENY (or a CSP frame-ancestors rule)."),
    (r"x-content-type|nosniff", "Send X-Content-Type-Options: nosniff."),
    (r"x-powered-by|version information|leaks information|server leaks", "Remove version banners and technology headers from responses."),
    (r"permissions policy|cross-origin|referrer", "Add the missing security header; it is cheap hardening, do it once in the web server or framework."),
    (r"debug|werkzeug|stack trace|verbose error", "Turn debug mode off in production and show generic error pages."),
    (r"password|credential|secret|token|api.?key", "Move the value out of the code into environment variables or a secret manager, and rotate it."),
    (r"privileged|docker\.sock|cap_add|network_mode", "Remove extra privileges from the container; give it only what it needs."),
    (r"\buser\b.*root|root user|run as root|\buser\b instruction", "Add a USER instruction so the container does not run as root."),
    (r":latest|latest tag|unpinned|pin", "Pin the version (image tag with digest, library version) so builds are reproducible."),
]
KIND_ADVICE = {
    "secret": "Treat the secret as leaked: revoke and replace it now, remove it from the code and from the git history, and load secrets from the environment.",
    "dependency": "Update the library to a patched version; if there is none, replace it or limit how it is used.",
    "runtime": "Fix the behaviour of the running site as described in the finding (usually a header, cookie or form setting).",
    "config": "Change the configuration as the finding describes and keep it in version control.",
    "code": "Review the code at the location and apply the fix described in the rule.",
}


def mitigation_for(kind: str, rule: str, message: str) -> str:
    # A dependency finding already says which version fixes it: that is the best advice.
    fix = re.search(r"(Fix:[^.]*(?:\.\d[^.]*)*\.|Fixed in:[^.]*(?:\.\d[^.]*)*\.)", message)
    if kind == "dependency":
        base = KIND_ADVICE["dependency"]
        return f"{base} {fix.group(1)}" if fix else base
    text = f"{rule} {message}".lower()
    if kind == "secret":
        return KIND_ADVICE["secret"]
    for pattern, advice in ADVICE:
        if re.search(pattern, text):
            return advice
    return KIND_ADVICE.get(kind, KIND_ADVICE["code"])


# ---------------------------------------------------------------- the register


@dataclass
class Context:
    exposure: str = "internet"
    data: str = "personal"

    def __post_init__(self):
        if self.exposure not in EXPOSURES:
            raise ValueError(f"exposure must be one of {sorted(EXPOSURES)}")
        if self.data not in DATA:
            raise ValueError(f"data must be one of {sorted(DATA)}")


@dataclass
class Risk:
    id: str
    title: str
    kind: str
    tools: list[str]
    rule: str
    severity: Severity
    where: list[str]
    count: int
    likelihood: int
    impact: int
    reasons: list[str]
    mitigation: str

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def level(self) -> str:
        return level_for(self.score)

    @property
    def target(self) -> str:
        return TARGETS[self.level]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "kind": self.kind, "tools": self.tools, "rule": self.rule,
            "tool_severity": self.severity.label, "where": self.where, "occurrences": self.count,
            "likelihood": self.likelihood, "impact": self.impact, "score": self.score, "level": self.level,
            "reasons": self.reasons, "mitigation": self.mitigation, "suggested_target": self.target,
        }  # fmt: skip


def score_group(kind: str, severity: Severity, ctx: Context) -> tuple[int, int, list[str]]:
    """Likelihood, impact and the reasons for both."""
    base_l, why_l = KIND_LIKELIHOOD.get(kind, KIND_LIKELIHOOD["code"])
    shift_e, why_e = EXPOSURES[ctx.exposure]
    likelihood = clamp(base_l + shift_e)
    reasons = [f"Likelihood {base_l}: {why_l}."]
    if shift_e:
        reasons.append(f"Likelihood {shift_e:+d}: {why_e}.")
    base_i = SEVERITY_IMPACT[severity]
    impact = base_i
    reasons.append(f"Impact {base_i}: the tool rates it {severity.label}.")
    shift_d, why_d = DATA[ctx.data]
    # Sensitive data raises the impact only of serious weaknesses (high, critical): a missing header does
    # not become a disaster because the database holds personal data. Public data lowers it for everything.
    if shift_d and (severity >= Severity.HIGH or shift_d < 0):
        impact += shift_d
        reasons.append(f"Impact {shift_d:+d}: {why_d}.")
    return likelihood, clamp(impact), reasons


def assess(findings: list[Finding], ctx: Context | None = None) -> list[Risk]:
    """One risk per kind of problem (tool + rule), listing every place it occurs."""
    ctx = ctx or Context()
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.category, f.rule or f.message[:60]), []).append(f)
    risks = []
    for (kind, rule), items in groups.items():
        severity = max(f.severity for f in items)
        lead = max(items, key=lambda f: f.severity)
        places = []
        for f in items:
            place = f"{f.file}:{f.line}" if f.line else f.file
            if place and place not in places:
                places.append(place)
        likelihood, impact, reasons = score_group(kind, severity, ctx)
        risks.append(
            Risk(
                id="", title=" ".join(lead.message.split())[:160] or rule, kind=kind,
                tools=sorted({f.tool for f in items}), rule=rule, severity=severity,
                where=places[:5] + ([f"... and {len(places) - 5} more"] if len(places) > 5 else []),
                count=len(items), likelihood=likelihood, impact=impact, reasons=reasons,
                mitigation=mitigation_for(kind, rule, lead.message),
            )
        )  # fmt: skip
    risks.sort(key=lambda r: (-r.score, -r.severity, -r.count, r.rule))
    for n, r in enumerate(risks, 1):
        r.id = f"R-{n:03d}"
    return risks


def matrix(risks: list[Risk]) -> dict[tuple[int, int], list[str]]:
    cells: dict[tuple[int, int], list[str]] = {}
    for r in risks:
        cells.setdefault((r.likelihood, r.impact), []).append(r.id)
    return cells


# ---------------------------------------------------------------- reading reports


@dataclass
class Source:
    path: str
    root: str
    kind: str
    findings: list[Finding] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def gaps(self) -> list[str]:
        return [
            f"{t.get('name', '?')}: {t.get('status')} ({str(t.get('detail', ''))[:120]})"
            for t in self.tools
            if t.get("status") in (ERROR, UNAVAILABLE)
        ]


def load_report(path: str) -> Source:
    """Read a JSON report written by `polyscan scan/dast --json`. Raises ValueError if it is not one.

    The file is data from outside: every field is checked, and nothing in it is ever executed."""
    p = Path(path)
    try:
        if p.stat().st_size > MAX_REPORT_BYTES:
            raise ValueError(f"{path}: file is too large to be a polyscan report")
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot read the file ({exc.strerror or exc})") from None
    except json.JSONDecodeError:
        raise ValueError(f"{path}: not a JSON file") from None
    if not isinstance(data, dict) or "polyscan" not in data or not isinstance(data.get("findings"), list):
        raise ValueError(f"{path}: not a polyscan JSON report (write one with --json)")
    findings = []
    for i, item in enumerate(data["findings"]):
        try:
            findings.append(
                Finding(
                    tool=str(item["tool"]), severity=Severity.parse(str(item["severity"])), rule=str(item.get("rule", "")),
                    message=str(item.get("message", "")), file=str(item.get("file", "")), line=int(item.get("line") or 0),
                    category=str(item.get("category", "code")), language=str(item.get("language", "")),
                )
            )  # fmt: skip
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError(f"{path}: finding number {i + 1} is malformed") from None
    tools = [t for t in data.get("tools") or [] if isinstance(t, dict)]
    notes = [str(n) for n in data.get("notes") or []]
    return Source(path, str(data.get("root", "")), str(data.get("kind", "folder")), findings, tools, notes)


def merge(sources: list[Source]) -> list[Finding]:
    """All findings, without exact repeats (two reports can overlap)."""
    seen, out = set(), []
    for s in sources:
        for f in s.findings:
            key = (f.tool, f.rule, f.file, f.line, f.message)
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out
