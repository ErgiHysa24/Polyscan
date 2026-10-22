"""Writes the risk register as terminal text, Markdown, HTML or JSON.

Text that came from scanned code or from a report file is untrusted: the same
escaping as in report.py is used (HTML escape plus a strict CSP, Markdown
neutralised, control characters removed from the terminal)."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .report import CSS, _clean, _e, _md
from .risk import DATA, EXPOSURES, LEVEL_UPPER, LEVELS, TARGETS, Context, Risk, Source, level_for, matrix

ORDER = list(reversed(LEVELS))  # critical first


def counts(risks: list[Risk]) -> Counter:
    return Counter(r.level for r in risks)


def gaps_of(sources: list[Source]) -> list[str]:
    return [f"{s.path}: {g}" for s in sources for g in s.gaps]


def notes_of(sources: list[Source]) -> list[str]:
    return [n for s in sources for n in s.notes]


def method_lines() -> list[str]:
    return [
        "risk score = likelihood (1-5) x impact (1-5), from 1 to 25",
        "levels: 1-5 low, 6-12 medium, 13-19 high, 20-25 critical",
        "likelihood starts from the kind of finding (secret 4, runtime 3, dependency 3, code 3, configuration 2) "
        "and moves by +1 for an internet-facing application, -1 for one that runs on a single machine",
        "impact starts from the tool's severity (critical 5, high 4, medium 3, low 2, info 1); personal data adds 1 "
        "to high and critical findings, public data subtracts 1 from all",
        "this is a transparent heuristic, not a measurement: read the reasons of each risk and adjust what you disagree with",
    ]


# ------------------------------------------------------------------ JSON


def to_json(ctx: Context, risks: list[Risk], sources: list[Source]) -> str:
    c = counts(risks)
    data = {
        "polyscan": __version__,
        "kind": "risk-assessment",
        "context": {"exposure": ctx.exposure, "data": ctx.data},
        "sources": [{"file": s.path, "root": s.root, "kind": s.kind} for s in sources],
        "summary": {name: c.get(name, 0) for name in ORDER},
        "coverage_gaps": gaps_of(sources),
        "notes": notes_of(sources),
        "matrix": [{"likelihood": l, "impact": i, "risks": ids} for (l, i), ids in sorted(matrix(risks).items())],
        "method": method_lines(),
        "risks": [r.to_dict() for r in risks],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------ terminal


def to_terminal(ctx: Context, risks: list[Risk], sources: list[Source], limit: int = 15) -> str:
    c = counts(risks)
    out = [f"polyscan risk assessment  -  exposure: {ctx.exposure}, data: {ctx.data}", ""]
    out.append("  ".join(f"{name} {c.get(name, 0)}" for name in ORDER))
    gaps = gaps_of(sources)
    if gaps:
        out += ["", "WARNING: some checks did not run, so this register may be incomplete:"] + [f"  - {_clean(g)}" for g in gaps]
    for note in notes_of(sources):
        out.append(f"NOTE: {_clean(note)}")
    out.append("")
    if not risks:
        out.append("No risks in the reports." + (" (but see the warning above)" if gaps else ""))
    for r in risks[:limit]:
        out.append(f"{r.id}  {r.level.upper():8} {r.score:2} (L{r.likelihood} x I{r.impact})  {_clean(r.title)[:110]}")
        out.append(f"        where: {_clean(', '.join(r.where))[:150]}")
        out.append(f"        do: {_clean(r.mitigation)[:200]}  [{r.target}]")
    if len(risks) > limit:
        out.append(f"... and {len(risks) - limit} more in the full report.")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ markdown


def to_markdown(ctx: Context, risks: list[Risk], sources: list[Source]) -> str:
    c = counts(risks)
    lines = ["## Risk assessment", "", f"Exposure: **{ctx.exposure}** - data: **{ctx.data}**", ""]
    lines.append(" | ".join(f"**{name}** {c.get(name, 0)}" for name in ORDER))
    lines.append("")
    gaps = gaps_of(sources)
    if gaps:
        lines += ["> **Some checks did not run, so this register may be incomplete:**"] + [f"> - {_md(g, 300)}" for g in gaps] + [""]
    lines += [f"> {_md(n, 400)}" for n in notes_of(sources)]
    if risks:
        lines += ["| ID | Level | Score | Risk | Where | What to do | By when |", "|---|---|---|---|---|---|---|"]
        for r in risks:
            lines.append(
                f"| {r.id} | {r.level} | {r.score} (L{r.likelihood}xI{r.impact}) | {_md(r.title, 120)} | "
                f"{_md(', '.join(r.where), 100)} | {_md(r.mitigation, 220)} | {_md(r.target)} |"
            )
    else:
        lines.append("No risks in the reports.")
    lines += ["", "<details><summary>How the score is computed</summary>", ""] + [f"- {_md(m, 400)}" for m in method_lines()] + ["", "</details>"]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ html

RISK_CSS = """
.lvl-critical{color:var(--critical)}.lvl-high{color:var(--high)}.lvl-medium{color:var(--medium)}.lvl-low{color:var(--low)}
.matrix{table-layout:fixed}.matrix td{height:34px}.matrix td,.matrix th{text-align:center;padding:6px}td b{white-space:nowrap}.matrix th{font-size:11px}
.m-low{background:rgba(21,101,160,.18)}.m-medium{background:rgba(178,106,0,.25)}
.m-high{background:rgba(198,40,40,.28)}.m-critical{background:rgba(139,29,44,.45)}
.reasons{margin:4px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
details{margin:8px 0}summary{cursor:pointer;color:var(--muted)}
"""


def _matrix_html(risks: list[Risk]) -> str:
    cells = matrix(risks)
    rows = ['<tr><th></th><th colspan="5">Impact</th></tr><tr><th>Likelihood</th>' + "".join(f"<th>{i}</th>" for i in range(1, 6)) + "</tr>"]
    for likelihood in range(5, 0, -1):
        tds = []
        for impact in range(1, 6):
            ids = cells.get((likelihood, impact), [])
            tds.append(f'<td class="m-{level_for(likelihood * impact)}">{len(ids) or ""}</td>')
        rows.append(f"<tr><th>{likelihood}</th>{''.join(tds)}</tr>")
    return '<div class="wrap"><table class="matrix">' + "".join(rows) + "</table></div><p class='muted'>Each cell shows how many risks have that likelihood and impact; the register below lists them.</p>"


def to_html(ctx: Context, risks: list[Risk], sources: list[Source]) -> str:
    c = counts(risks)
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = "".join(f'<div class="card"><b class="lvl-{n}">{c.get(n, 0)}</b><span>{n}</span></div>' for n in ORDER)
    warn = ""
    gaps = gaps_of(sources)
    if gaps:
        warn += '<div class="warn">Some checks did not run, so this register may be incomplete:<ul>' + "".join(f"<li>{_e(g)}</li>" for g in gaps) + "</ul></div>"
    warn += "".join(f'<div class="warn">{_e(n)}</div>' for n in notes_of(sources))
    rows = []
    for r in risks:
        reasons = "".join(f"<li>{_e(x)}</li>" for x in r.reasons)
        rows.append(
            f'<tr><td><b>{_e(r.id)}</b></td><td class="sev lvl-{r.level}">{_e(r.level)}<br>{r.score}<br>'
            f'<span class="muted">L{r.likelihood} x I{r.impact}</span></td>'
            f"<td><b>{_e(r.title)}</b><br><span class='muted'>{_e(r.kind)} &middot; {_e(', '.join(r.tools))} &middot; {_e(r.rule)} &middot; {r.count} occurrence(s)</span>"
            f"<br><code>{_e(', '.join(r.where))}</code><details><summary>why this score</summary><ul class='reasons'>{reasons}</ul></details></td>"
            f"<td>{_e(r.mitigation)}<br><span class='muted'>Suggested: {_e(r.target)}</span></td></tr>"
        )
    table = (
        '<div class="wrap"><table class="f"><tr><th>ID</th><th>Risk level</th><th>Risk</th><th>What to do</th></tr>' + "".join(rows) + "</table></div>"
        if rows else '<p class="muted">No risks in the reports.</p>'
    )
    method = "".join(f"<li>{_e(m)}</li>" for m in method_lines())
    targets = "".join(f"<li><b>{n}</b> ({LEVEL_UPPER[n]} or less): {_e(TARGETS[n])}</li>" for n in LEVELS)
    sources_html = "<br>".join(_e(s.path) for s in sources)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>polyscan risk assessment</title><style>{CSS}{RISK_CSS}</style></head>
<body><main>
<h1>Risk assessment</h1>
<p class="sub">{_e(when)} &middot; polyscan {_e(__version__)}<br>Exposure: {_e(ctx.exposure)} ({_e(EXPOSURES[ctx.exposure][1])})<br>Data: {_e(ctx.data)} ({_e(DATA[ctx.data][1])})<br>From: {sources_html}</p>
<div class="cards">{cards}</div>{warn}
<h2>Risk matrix</h2>{_matrix_html(risks)}
<h2>Risk register</h2>{table}
<h2>How the score is computed</h2><ul>{method}</ul>
<h2>Suggested response times</h2><ul>{targets}</ul>
</main></body></html>
"""
