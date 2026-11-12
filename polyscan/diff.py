"""Retest: compare two polyscan JSON reports (before and after the fixes).

    polyscan diff before.json after.json [--json FILE] [--markdown FILE] [--html FILE] [--fail-on LEVEL]

Every finding of the two reports ends up in exactly one group:

  * fixed        - in the first report, not in the second, AND the tool that found it ran fine the
                   second time;
  * not verified - in the first report, not in the second, but the tool did NOT run correctly the
                   second time (error, not installed, skipped). It is not proof of a fix, so it is
                   never counted as one: this is the mistake a retest must not make;
  * still open   - in both;
  * new          - only in the second.

Findings are matched by tool, rule and file, not by line: a fix in the same file moves the lines of
everything below it. When a rule fires several times in one file, the counts are compared (3 before,
1 after = 2 fixed, 1 still open).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .models import OK, Finding, Severity
from .report import CSS, _clean, _e, _md
from .risk import Source

GROUPS = ("fixed", "not_verified", "still_open", "new")
LABEL = {"fixed": "Fixed", "not_verified": "Not verified (tool did not run)", "still_open": "Still open", "new": "New"}


def key(f: Finding) -> tuple[str, str, str]:
    return (f.tool, f.rule or " ".join(f.message.split())[:80], f.file)


@dataclass
class Diff:
    before: Source
    after: Source
    groups: dict[str, list[Finding]] = field(default_factory=lambda: {g: [] for g in GROUPS})

    def counts(self) -> dict[str, int]:
        return {g: len(self.groups[g]) for g in GROUPS}

    def after_gaps(self) -> list[str]:
        return self.after.gaps

    def to_dict(self) -> dict:
        return {
            "polyscan": __version__, "kind": "retest",
            "before": {"file": self.before.path, "root": self.before.root, "findings": len(self.before.findings)},
            "after": {"file": self.after.path, "root": self.after.root, "findings": len(self.after.findings)},
            "summary": self.counts(), "coverage_gaps_after": self.after_gaps(),
            "groups": {g: [f.to_dict() for f in self.groups[g]] for g in GROUPS},
        }  # fmt: skip


def ran_ok(source: Source) -> set[str]:
    """Tools that ran correctly in a report. Old reports without a tool list: assume the tools of its findings ran."""
    if not source.tools:
        return {f.tool for f in source.findings}
    return {str(t.get("name")) for t in source.tools if t.get("status") == OK}


def compare(before: Source, after: Source) -> Diff:
    d = Diff(before, after)
    ok_after = ran_ok(after)
    old: dict[tuple, list[Finding]] = {}
    new: dict[tuple, list[Finding]] = {}
    for f in before.findings:
        old.setdefault(key(f), []).append(f)
    for f in after.findings:
        new.setdefault(key(f), []).append(f)
    for k in sorted(set(old) | set(new)):
        a, b = old.get(k, []), new.get(k, [])
        common = min(len(a), len(b))
        d.groups["still_open"] += b[:common]
        d.groups["new"] += b[common:]
        gone = a[common:]
        tool = k[0]
        # "gitleaks-history" reports findings under the tool name "gitleaks": accept either name
        verified = tool in ok_after or any(t.startswith(tool) for t in ok_after)
        d.groups["fixed" if verified else "not_verified"] += gone
    for g in GROUPS:
        d.groups[g].sort(key=lambda f: (-f.severity, f.tool, f.file, f.line))
    return d


def worst(findings: list[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)


# ------------------------------------------------------------------ output
def _line(f: Finding) -> str:
    where = f"{f.file}:{f.line}" if f.line else f.file
    return f"{f.severity.label.upper():8} {f.tool:14} {f.rule[:40]:40} {where}"


def to_terminal(d: Diff, limit: int = 10) -> str:
    c = d.counts()
    out = [f"polyscan retest  -  before: {_clean(d.before.path)}  after: {_clean(d.after.path)}", ""]
    out.append("  ".join(f"{LABEL[g].split(' (')[0].lower()} {c[g]}" for g in GROUPS))
    if d.after_gaps():
        out += ["", "WARNING: some checks did not run in the second report; what they found before is 'not verified':"]
        out += [f"  - {_clean(g)}" for g in d.after_gaps()]
    for g in ("new", "not_verified", "still_open", "fixed"):
        items = d.groups[g]
        if not items:
            continue
        out += ["", f"{LABEL[g]} ({len(items)}):"]
        out += [f"  {_clean(_line(f))}" for f in items[:limit]]
        if len(items) > limit:
            out.append(f"  ... and {len(items) - limit} more")
    return "\n".join(out) + "\n"


def to_json(d: Diff) -> str:
    return json.dumps(d.to_dict(), indent=2, ensure_ascii=False)


def to_markdown(d: Diff, limit: int = 50) -> str:
    c = d.counts()
    lines = ["## Retest", "", " | ".join(f"**{LABEL[g]}** {c[g]}" for g in GROUPS), ""]
    if d.after_gaps():
        lines += ["> **Some checks did not run in the second report**, so what they found before is *not verified*, not fixed:"]
        lines += [f"> - {_md(g, 300)}" for g in d.after_gaps()] + [""]
    for g in ("new", "not_verified", "still_open", "fixed"):
        items = d.groups[g]
        if not items:
            continue
        lines += [f"### {LABEL[g]} ({len(items)})", "", "| Severity | Tool | Rule | Where | Finding |", "|---|---|---|---|---|"]
        for f in items[:limit]:
            where = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"| {f.severity.label} | {_md(f.tool)} | {_md(f.rule, 60)} | {_md(where, 100)} | {_md(f.message, 160)} |")
        if len(items) > limit:
            lines.append(f"\n... and {len(items) - limit} more (see the JSON report)")
        lines.append("")
    return "\n".join(lines) + "\n"


def to_html(d: Diff) -> str:
    c = d.counts()
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    colors = {"fixed": "low", "not_verified": "medium", "still_open": "high", "new": "critical"}
    cards = "".join(f'<div class="card"><b class="{colors[g]}">{c[g]}</b><span>{_e(LABEL[g])}</span></div>' for g in GROUPS)
    warn = ""
    if d.after_gaps():
        warn = '<div class="warn">Some checks did not run in the second report, so what they found before is <b>not verified</b>, not fixed:<ul>' + "".join(f"<li>{_e(g)}</li>" for g in d.after_gaps()) + "</ul></div>"
    sections = []
    for g in ("new", "not_verified", "still_open", "fixed"):
        items = d.groups[g]
        if not items:
            continue
        rows = "".join(
            f"<tr><td class='sev {_e(f.severity.label)}'>{_e(f.severity.label)}</td><td>{_e(f.tool)}</td><td><code>{_e(f.rule)}</code></td>"
            f"<td><code>{_e(f.file)}{':' + str(f.line) if f.line else ''}</code></td><td>{_e(f.message)}</td></tr>"
            for f in items[:500]
        )
        sections.append(f"<h2>{_e(LABEL[g])} ({len(items)})</h2><div class='wrap'><table class='f'><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Where</th><th>Finding</th></tr>{rows}</table></div>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>polyscan retest</title><style>{CSS}</style></head>
<body><main>
<h1>Retest</h1>
<p class="sub">{_e(when)} &middot; polyscan {_e(__version__)}<br>Before: {_e(d.before.path)}<br>After: {_e(d.after.path)}</p>
<div class="cards">{cards}</div>{warn}
{''.join(sections) or '<p class="muted">Both reports are empty.</p>'}
<p class="muted">Findings are matched by tool, rule and file (not by line). A finding that disappeared is counted as fixed only if its tool ran correctly the second time.</p>
</main></body></html>
"""
