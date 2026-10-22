"""Terminal, HTML and JSON reports."""

from __future__ import annotations

import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .models import ERROR, OK, SKIPPED, UNAVAILABLE, Severity
from .scanner import ScanResult

ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
STATUS_TEXT = {
    OK: "ok",
    SKIPPED: "nothing to scan",
    UNAVAILABLE: "NOT RUN (missing)",
    ERROR: "FAILED",
}


def counts(result: ScanResult) -> Counter:
    return Counter(f.severity for f in result.findings)


# ------------------------------------------------------------------- json


def to_json(result: ScanResult) -> str:
    c = counts(result)
    data = {
        "polyscan": __version__,
        "root": result.root,
        "languages": result.languages,
        "summary": {s.label: c.get(s, 0) for s in ORDER},
        "tools": [t.to_dict() for t in result.tools],
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# --------------------------------------------------------------- terminal

COLORS = {
    Severity.CRITICAL: "1;97;41",
    Severity.HIGH: "1;31",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "2",
}


def _use_color(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def _clean(text: str) -> str:
    """Drop control characters (such as ANSI escapes) that came from scanned code."""
    return "".join(ch if ch.isprintable() else " " for ch in text)


def to_terminal(result: ScanResult, limit: int = 30, stream=None) -> str:
    stream = stream or sys.stdout
    color = _use_color(stream)

    def paint(text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if color else text

    lines = []
    langs = ", ".join(f"{k} ({v})" for k, v in result.languages.items()) or "none detected"
    lines.append(f"polyscan {__version__}  -  {result.root}")
    lines.append(f"Languages: {langs}")
    lines.append("")
    lines.append("Tools")
    for t in result.tools:
        status = STATUS_TEXT.get(t.status, t.status)
        if t.status in (ERROR, UNAVAILABLE):
            status = paint(status, "1;31")
        extra = f"{len(t.findings)} findings, " if t.status == OK else ""
        lines.append(f"  {t.name:<12} {status:<22} {extra}{_clean(t.detail)}")
    lines.append("")

    c = counts(result)
    lines.append("Findings: " + "  ".join(paint(f"{s.label} {c.get(s, 0)}", COLORS[s]) for s in ORDER))
    findings = result.findings
    for f in findings[:limit]:
        where = f"{_clean(f.file)}:{f.line}" if f.line else _clean(f.file)
        sev = paint(f.severity.label.upper().ljust(8), COLORS[f.severity])
        lines.append(f"  {sev} {where}")
        lines.append(f"           [{f.tool}] {_clean(f.rule)}")
        lines.append(f"           {_clean(f.message)[:160]}")
    if len(findings) > limit:
        lines.append(f"  ... and {len(findings) - limit} more. Use --html or --json for the full list.")
    if result.had_gaps:
        lines.append("")
        lines.append(paint("WARNING: some checks did not run. A clean result does NOT mean the code is safe.", "1;31"))
    return "\n".join(lines)


# --------------------------------------------------------------- markdown


def _md(value, limit: int = 140) -> str:
    """Make scanned text harmless inside a Markdown table cell."""
    text = " ".join(str(value).split())[:limit]
    for ch in "\\`*_{}[]()#+-!|~":
        text = text.replace(ch, "\\" + ch)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_markdown(result: ScanResult, limit: int = 20) -> str:
    """Short summary for the GitHub job page."""
    c = counts(result)
    lines = ["## polyscan", ""]
    lines.append(" | ".join(f"**{s.label}** {c.get(s, 0)}" for s in ORDER))
    lines.append("")
    if result.had_gaps:
        lines += ["> **Some checks did not run.** A clean result does not mean the code is safe.", ""]
    lines += ["| Tool | Status | Findings |", "|---|---|---|"]
    for t in result.tools:
        found = len(t.findings) if t.status == OK else "-"
        lines.append(f"| {_md(t.name)} | {_md(STATUS_TEXT.get(t.status, t.status))} | {found} |")
    findings = result.findings
    if findings:
        lines += ["", "| Severity | Where | Rule |", "|---|---|---|"]
        for f in findings[:limit]:
            where = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"| {f.severity.label} | {_md(where, 80)} | {_md(f.rule, 80)} |")
        if len(findings) > limit:
            lines.append(f"\n...and {len(findings) - limit} more in the full report.")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1c2330;--muted:#5d6676;--line:#dfe3ea;
--critical:#8b1d2c;--high:#c62828;--medium:#b26a00;--low:#1565a0;--info:#6b7280;--bad:#c62828}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--card:#1a212c;--text:#e6eaf0;--muted:#9aa4b2;
--line:#2b3442;--critical:#ff6b7d;--high:#ff7b72;--medium:#e3a53b;--low:#6cb6ff;--info:#9aa4b2;--bad:#ff7b72}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.sub{color:var(--muted);margin:0 0 20px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.card b{display:block;font-size:26px;line-height:1.1}.card span{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}
.sev{font-weight:700;text-transform:uppercase;font-size:12px}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
code,pre{font:13px/1.4 ui-monospace,Consolas,monospace}
pre{margin:6px 0 0;padding:8px;background:var(--bg);border-radius:6px;overflow-x:auto;white-space:pre-wrap}
.warn{border:1px solid var(--bad);color:var(--bad);border-radius:8px;padding:12px;margin:16px 0;font-weight:600}
.muted{color:var(--muted)}
@media (max-width:640px){
table.f tr:first-child{display:none}
table.f tr{display:block;padding:8px 0;border-bottom:1px solid var(--line)}
table.f td{display:block;border:0;padding:2px 10px}
}
"""


def _e(value) -> str:
    """Escape any value for HTML. Everything from scanned code goes through this."""
    return html.escape(str(value), quote=True)


def to_html(result: ScanResult) -> str:
    c = counts(result)
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    langs = ", ".join(f"{k} ({v})" for k, v in result.languages.items()) or "none detected"

    cards = "".join(
        f'<div class="card"><b class="{s.label}">{c.get(s, 0)}</b><span>{s.label}</span></div>' for s in ORDER
    )
    tool_rows = []
    for t in result.tools:
        cls = ' class="high"' if t.status in (ERROR, UNAVAILABLE) else ""
        found = len(t.findings) if t.status == OK else "-"
        tool_rows.append(
            f"<tr><td>{_e(t.name)}</td><td{cls}>{_e(STATUS_TEXT.get(t.status, t.status))}</td>"
            f"<td>{found}</td><td class='muted'>{_e(t.detail)}</td></tr>"
        )
    tool_rows = "".join(tool_rows)
    rows = []
    for f in result.findings:
        where = f"{f.file}:{f.line}" if f.line else f.file
        snippet = f"<pre>{_e(f.snippet)}</pre>" if f.snippet else ""
        rows.append(
            f'<tr><td class="sev {f.severity.label}">{_e(f.severity.label)}</td>'
            f"<td>{_e(f.tool)}<br><span class='muted'>{_e(f.category)}</span></td>"
            f"<td><code>{_e(where)}</code></td>"
            f"<td><b>{_e(f.rule)}</b><br>{_e(f.message)}{snippet}</td></tr>"
        )
    findings_html = (
        '<div class="wrap"><table class="f"><tr><th>Severity</th><th>Tool</th><th>Where</th><th>Details</th></tr>'
        + "".join(rows)
        + "</table></div>"
        if rows
        else '<p class="muted">No findings.</p>'
    )
    warn = (
        '<div class="warn">Some checks did not run (see the tool table). '
        "A clean result does not mean the code is safe.</div>"
        if result.had_gaps
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>polyscan report</title><style>{CSS}</style></head>
<body><main>
<h1>polyscan report</h1>
<p class="sub">{_e(result.root)}<br>{_e(when)} &middot; polyscan {_e(__version__)} &middot; languages: {_e(langs)}</p>
<div class="cards">{cards}</div>{warn}
<h2>Tools</h2>
<div class="wrap"><table><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Detail</th></tr>{tool_rows}</table></div>
<h2>Findings</h2>{findings_html}
</main></body></html>
"""
