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
STATUS_TAG = {OK: "[ ok ]", ERROR: "[FAIL]", UNAVAILABLE: "[miss]", SKIPPED: "[skip]"}  # like a terminal would print it
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
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),  # used by `polyscan history`
        "root": result.root,
        "kind": result.kind,
        "notes": result.notes,
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
    lines.append(f"Target: {_clean(result.root)}" if result.kind in ("site", "host") else f"Languages: {langs}")
    for note in result.notes:
        lines.append(paint("NOTE: " + _clean(note), "1;33"))
    lines.append("")
    lines.append("Tools")
    name_width = max([12] + [len(t.name) for t in result.tools])
    for t in result.tools:
        status = STATUS_TEXT.get(t.status, t.status)
        if t.status in (ERROR, UNAVAILABLE):
            status = paint(status, "1;31")
        extra = f"{len(t.findings)} findings, " if t.status == OK else ""
        lines.append(f"  {t.name:<{name_width}} {status:<22} {extra}{_clean(t.detail)}")
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
        lines.append(paint("WARNING: some checks did not run. A clean result does NOT mean it is safe.", "1;31"))
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
        lines += ["> **Some checks did not run.** A clean result does not mean it is safe.", ""]
    lines += [f"> {_md(n, 400)}" for n in result.notes] + ([""] if result.notes else [])
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
:root{--bg:#f3f5f4;--card:#fbfcfb;--text:#14201c;--muted:#566660;--line:#c9d1cd;--accent:#0b6b57;
--critical:#a3122a;--high:#c8501e;--medium:#9a6b00;--low:#2b62a8;--info:#66736e;--bad:#a3122a;
--mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,"DejaVu Sans Mono",monospace;
--sans:system-ui,-apple-system,"Segoe UI",Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#0d1512;--card:#121d19;--text:#d5e2dc;--muted:#8da099;
--line:#27352f;--accent:#5fd0a8;--critical:#ff6b81;--high:#ff9461;--medium:#e0b040;--low:#7fb2f0;--info:#8da099;--bad:#ff6b81}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans)}
main{max-width:1040px;margin:0 auto;padding:28px 18px 56px}
.prompt{font:14px/1.4 var(--mono);color:var(--accent);margin:0 0 10px}
.prompt::before{content:"$ ";color:var(--muted)}
h1{font:700 26px/1.2 var(--mono);letter-spacing:-.01em;margin:0 0 6px}
h2{font:700 15px/1.3 var(--mono);margin:34px 0 12px;display:flex;align-items:center;gap:12px}
h2::before{content:"##";color:var(--accent)}
h2::after{content:"";flex:1;border-top:1px dashed var(--line)}
.sub{color:var(--muted);margin:0 0 22px;word-break:break-all;font:13px/1.6 var(--mono)}
.bars{font:14px/1.75 var(--mono);margin:0 0 4px;padding:14px 16px;background:var(--card);border:1px solid var(--line);
border-left:3px solid var(--accent);border-radius:2px;white-space:pre;overflow-x:auto}
.bars .off{color:var(--line)}.bars b{font-weight:700}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
th,td{text-align:left;padding:8px 11px;border-bottom:1px dashed var(--line);vertical-align:top}
th{font:700 12px/1.4 var(--mono);color:var(--muted);border-bottom:1px solid var(--line);background:var(--bg)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}
.sev{font:700 12.5px/1.5 var(--mono);white-space:nowrap}
.sev::before{content:"[";color:var(--muted);font-weight:400}.sev::after{content:"]";color:var(--muted);font-weight:400}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
code,pre{font:13px/1.45 var(--mono)}
pre{margin:6px 0 0;padding:8px 10px;background:var(--bg);border-left:2px solid var(--line);overflow-x:auto;white-space:pre-wrap}
.warn{border:1px solid var(--bad);border-left-width:3px;color:var(--bad);padding:11px 14px;margin:16px 0;font-weight:600;background:var(--card)}
.warn::before{content:"! ";font-family:var(--mono)}
.muted{color:var(--muted)}a{color:var(--accent)}
.foot{margin-top:40px;padding-top:12px;border-top:1px dashed var(--line);font:12px/1.5 var(--mono);color:var(--muted)}
@media (max-width:640px){
table.f tr:first-child{display:none}
table.f tr{display:block;padding:8px 0;border-bottom:1px dashed var(--line)}
table.f td{display:block;border:0;padding:2px 10px}
}
@media print{body{background:#fff}.bars,table,.warn{background:#fff}}
"""


def bars(rows: list[tuple[str, int, str]], width: int = 28) -> str:
    """A bar chart made of characters, the way a terminal would print it:

        critical  ████████████░░░░░░░░░░░░░░░░  12

    rows are (label, count, css class). The longest bar is the largest count; a count above zero always
    shows at least one block, so a single critical finding is never invisible next to 400 low ones."""
    top = max((n for _, n, _ in rows), default=0) or 1
    pad = max((len(label) for label, _, _ in rows), default=0)
    lines = []
    for label, n, cls in rows:
        full = 0 if n <= 0 else max(1, round(n / top * width))
        lines.append(
            f'{_e(label.ljust(pad))}  <span class="{_e(cls)}">{"█" * full}</span><span class="off">{"░" * (width - full)}</span>  '
            f'<b class="{_e(cls)}">{n}</b>'
        )
    return '<div class="bars" role="img" aria-label="' + _e(", ".join(f"{label} {n}" for label, n, _ in rows)) + '">' + "\n".join(lines) + "</div>"



def _e(value) -> str:
    """Escape any value for HTML. Everything from scanned code goes through this."""
    return html.escape(str(value), quote=True)


def to_html(result: ScanResult) -> str:
    c = counts(result)
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    langs = ", ".join(f"{k} ({v})" for k, v in result.languages.items()) or "none detected"

    cards = bars([(s.label, c.get(s, 0), s.label) for s in ORDER])
    tool_rows = []
    for t in result.tools:
        cls = ' class="high"' if t.status in (ERROR, UNAVAILABLE) else ""
        found = len(t.findings) if t.status == OK else "-"
        tool_rows.append(
            f"<tr><td>{_e(t.name)}</td><td{cls}><code>{STATUS_TAG.get(t.status, "[ ?? ]")}</code> {_e(STATUS_TEXT.get(t.status, t.status))}</td>"
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
        "A clean result does not mean it is safe.</div>"
        if result.had_gaps
        else ""
    ) + "".join(f'<div class="warn">{_e(n)}</div>' for n in result.notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>polyscan report</title><style>{CSS}</style></head>
<body><main>
<p class="prompt">polyscan {_e({"site": "dast", "host": "ports"}.get(result.kind, "scan"))}</p>
<h1>Scan report</h1>
<p class="sub">{_e(result.root)}<br>{_e(when)} &middot; polyscan {_e(__version__)} &middot; {_e({"site": "site scan", "host": "host check"}.get(result.kind) or "languages: " + langs)}</p>
{cards}{warn}
<h2>Tools</h2>
<div class="wrap"><table><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Detail</th></tr>{tool_rows}</table></div>
<h2>Findings</h2>{findings_html}
</main></body></html>
"""
