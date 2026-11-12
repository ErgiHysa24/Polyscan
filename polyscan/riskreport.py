"""Writes the risk register as terminal text, Markdown, HTML or JSON.

Text that came from scanned code or from a report file is untrusted: the same
escaping as in report.py is used (HTML escape plus a strict CSP, Markdown
neutralised, control characters removed from the terminal)."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .report import CSS, _clean, _e, _md, bars
from .intel import Intel
from .treatment import Plan
from .risk import (
    DATA,
    EXPOSURES,
    LEVEL_UPPER,
    LEVELS,
    TARGETS,
    Context,
    Risk,
    Source,
    level_for,
    matrix,
)

ORDER = list(reversed(LEVELS))  # critical first


def counts(risks: list[Risk]) -> Counter:
    return Counter(r.level for r in risks)


def gaps_of(sources: list[Source]) -> list[str]:
    return [f"{s.path}: {g}" for s in sources for g in s.gaps]


def intel_gaps(intel: Intel | None) -> list[str]:
    return [f"threat intelligence: {p}" for p in intel.problems] if intel else []


def kev_mark(r: Risk) -> str:
    """'KEV' or 'EPSS 12.3%' for the register, empty when nothing is known."""
    if not r.intel:
        return ""
    if r.intel.get("kev"):
        return "KEV: exploited in the wild"
    scores = r.intel.get("epss") or {}
    if scores:
        return f"EPSS {max(s['epss'] for s in scores.values()):.1%}"
    return ""


def notes_of(sources: list[Source]) -> list[str]:
    return [n for s in sources for n in s.notes]


STATE_LABEL = {
    "untreated": "no decision yet", "accepted": "accepted", "acceptance-expired": "acceptance EXPIRED",
    "planned": "treatment planned", "overdue": "treatment OVERDUE", "done": "marked done but STILL FOUND",
}  # fmt: skip


def states(risks: list[Risk]) -> Counter:
    return Counter(r.state for r in risks)


def treatment_text(r: Risk) -> str:
    """'accept - Mario Rossi - until 2026-12-31 (only used in tests)'; empty for an untreated risk."""
    d = r.treatment
    if not d:
        return ""
    when = f"until {d.expires}" if d.decision == "accept" else (f"due {d.due}" if d.due else "")
    bits = [d.decision, STATE_LABEL.get(r.state, r.state), d.owner, when, d.ticket]
    text = " - ".join(b for b in bits if b)
    return text + (f" ({d.justification})" if d.justification else "")


def plan_warnings(plan: Plan | None) -> list[str]:
    return plan.warnings() if plan else []


def false_positive_lines(plan: Plan | None) -> list[str]:
    if not plan:
        return []
    return [
        f"{f.tool} {f.rule} {f.file}{':' + str(f.line) if f.line else ''} - {d.owner}: {d.justification}"
        for f, d in plan.false_positives
    ]


def method_lines() -> list[str]:
    return [
        "risk score = likelihood (1-5) x impact (1-5), from 1 to 25",
        "levels: 1-5 low, 6-12 medium, 13-19 high, 20-25 critical",
        (
            "likelihood starts from the kind of finding (secret 4, runtime 3, dependency 3, code 3, configuration 2) "
            "and moves by +1 for an internet-facing application, -1 for one that runs on a single machine"
        ),
        (
            "impact starts from the tool's severity (critical 5, high 4, medium 3, low 2, info 1); personal data adds 1 "
            "to high and critical findings, public data subtracts 1 from all"
        ),
        "this is a transparent heuristic, not a measurement: read the reasons of each risk and adjust what you disagree with",
        (
            "second opinion: every risk is also rated with the OWASP Risk Rating Methodology (16 factors from 0 to 9; likelihood and "
            "impact are averages; below 3 LOW, below 6 MEDIUM, else HIGH). Threat-agent factors come from the context, vulnerability "
            "factors from the finding, technical impact from STRIDE x severity; business impact and overrides from --factors"
        ),
        (
            "with threat intelligence (--intel, --kev-file, --epss-file): a CVE in the CISA KEV catalog sets the likelihood to 5; "
            "otherwise an EPSS probability of 10% or more adds 1. Nothing lowers a likelihood"
        ),
        (
            "threat links: CVE and CWE ids are reported by the tools; the OWASP Top 10 (2021) category, the STRIDE threat and the "
            "MITRE ATT&CK techniques are polyscan's own judgement from a fixed table (polyscan/threats.py), a starting point "
            "for a threat model and not an official mapping. 'by kind' means the tool gave no CWE, so the link comes from the "
            "kind of finding"
        ),
    ]


def threat_line(r: Risk) -> str:
    """One line for text and Markdown: 'CWE-89 | A03 Injection | STRIDE: ... | ATT&CK: T1190 ...' (empty if nothing known)."""
    t = r.threat
    if not t or (t.basis == "none" and not (t.cve or t.advisories or t.cwe)):
        return ""
    parts = []
    ids = t.cve or t.advisories
    if ids:
        parts.append(", ".join(ids[:3]) + (f" (+{len(ids) - 3})" if len(ids) > 3 else ""))
    if t.cwe:
        parts.append(", ".join(t.cwe))
    if t.owasp:
        parts.append(", ".join(t.owasp))
    if t.stride:
        parts.append("STRIDE: " + ", ".join(t.stride))
    if t.attack:
        parts.append("ATT&CK: " + ", ".join(f"{a['id']} {a['name']}" for a in t.attack))
    return " | ".join(parts) + (" (by kind)" if t.basis == "kind" else "")


# ------------------------------------------------------------------ JSON


def to_json(ctx: Context, risks: list[Risk], sources: list[Source], plan: Plan | None = None, intel: Intel | None = None) -> str:
    c = counts(risks)
    data = {
        "polyscan": __version__,
        "kind": "risk-assessment",
        "context": {"exposure": ctx.exposure, "data": ctx.data},
        "sources": [{"file": s.path, "root": s.root, "kind": s.kind} for s in sources],
        "summary": {name: c.get(name, 0) for name in ORDER},
        "coverage_gaps": gaps_of(sources) + intel_gaps(intel),
        "threat_intel": intel.to_dict() if intel else None,
        "notes": notes_of(sources),
        "matrix": [{"likelihood": l, "impact": i, "risks": ids} for (l, i), ids in sorted(matrix(risks).items())],
        "method": method_lines(),
        "risks": [r.to_dict() for r in risks],
        "treatment": {
            "file": plan.path if plan else None,
            "states": dict(states(risks)),
            "active": sum(r.active for r in risks),
            "warnings": plan_warnings(plan),
            "false_positives": [
                {**f.to_dict(), "decided_by": d.owner, "justification": d.justification, "entry": d.index}
                for f, d in (plan.false_positives if plan else [])
            ],
        },
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------ terminal


def to_terminal(ctx: Context, risks: list[Risk], sources: list[Source], limit: int = 15, plan: Plan | None = None, intel: Intel | None = None) -> str:
    c = counts(risks)
    out = [f"polyscan risk assessment  -  exposure: {ctx.exposure}, data: {ctx.data}", ""]
    out.append("  ".join(f"{name} {c.get(name, 0)}" for name in ORDER))
    gaps = gaps_of(sources) + intel_gaps(intel)
    if intel and intel.sources:
        out.append("threat intelligence: " + "; ".join(_clean(x) for x in intel.sources))
    if gaps:
        out += ["", "WARNING: some checks did not run, so this register may be incomplete:"] + [f"  - {_clean(g)}" for g in gaps]
    for note in notes_of(sources):
        out.append(f"NOTE: {_clean(note)}")
    if plan:
        st = states(risks)
        out.append("treatment: " + ", ".join(f"{STATE_LABEL[k]} {st[k]}" for k in STATE_LABEL if st.get(k))
                   + f"; false positives {len(plan.false_positives)}")  # fmt: skip
        out += [f"WARNING: {_clean(w)}" for w in plan_warnings(plan)]
    out.append("")
    if not risks:
        out.append("No risks in the reports." + (" (but see the warning above)" if gaps else ""))
    for r in risks[:limit]:
        mark = f"  [{kev_mark(r)}]" if kev_mark(r) else ""
        out.append(f"{r.id}  {r.level.upper():8} {r.score:2} (L{r.likelihood} x I{r.impact})  {_clean(r.title)[:110]}{mark}")
        out.append(f"        where: {_clean(', '.join(r.where))[:150]}")
        if threat_line(r):
            out.append(f"        threat: {_clean(threat_line(r))[:300]}")
        out.append(f"        do: {_clean(r.mitigation)[:200]}  [{r.target}]")
        if r.treatment:
            out.append(f"        decision: {_clean(treatment_text(r))[:220]}")
        if r.owasp:
            out.append(f"        OWASP Risk Rating: {r.owasp.short()}")
    if len(risks) > limit:
        out.append(f"... and {len(risks) - limit} more in the full report.")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ markdown


def to_markdown(ctx: Context, risks: list[Risk], sources: list[Source], plan: Plan | None = None, intel: Intel | None = None) -> str:
    c = counts(risks)
    lines = ["## Risk assessment", "", f"Exposure: **{ctx.exposure}** - data: **{ctx.data}**", ""]
    lines.append(" | ".join(f"**{name}** {c.get(name, 0)}" for name in ORDER))
    lines.append("")
    gaps = gaps_of(sources) + intel_gaps(intel)
    if intel and intel.sources:
        lines += ["Threat intelligence: " + "; ".join(_md(x, 200) for x in intel.sources), ""]
    if gaps:
        lines += ["> **Some checks did not run, so this register may be incomplete:**"] + [f"> - {_md(g, 300)}" for g in gaps] + [""]
    lines += [f"> {_md(n, 400)}" for n in notes_of(sources)]
    if plan:
        st = states(risks)
        lines += ["", "Treatment: " + ", ".join(f"{STATE_LABEL[k]} **{st[k]}**" for k in STATE_LABEL if st.get(k))
                  + f", false positives **{len(plan.false_positives)}**", ""]  # fmt: skip
        lines += [f"> ⚠ {_md(w, 300)}" for w in plan_warnings(plan)]
        lines.append("")
    if risks:
        lines += ["| ID | Level | Score | Risk | Threat (CWE / OWASP / STRIDE / ATT&CK) | Where | What to do | By when | Decision |", "|---|---|---|---|---|---|---|---|---|"]
        for r in risks:
            lines.append(
                f"| {r.id} | {r.level} | {r.score} (L{r.likelihood}xI{r.impact}) | {_md(r.title, 120)}{(' **' + _md(kev_mark(r)) + '**') if kev_mark(r) else ''} | "
                f"{_md(threat_line(r), 300)}{('<br>OWASP RR: ' + _md(r.owasp.short())) if r.owasp else ''} | {_md(', '.join(r.where), 100)} | {_md(r.mitigation, 220)} | {_md(r.target)} | {_md(treatment_text(r) or STATE_LABEL['untreated'], 200)} |"
            )
    else:
        lines.append("No risks in the reports.")
    fps = false_positive_lines(plan)
    if fps:
        lines += ["", f"<details><summary>{len(fps)} finding(s) marked as false positive</summary>", ""] + [f"- {_md(x, 300)}" for x in fps] + ["", "</details>"]
    lines += ["", "<details><summary>How the score is computed</summary>", ""] + [f"- {_md(m, 400)}" for m in method_lines()] + ["", "</details>"]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ html

RISK_CSS = """
.lvl-critical{color:var(--critical)}.lvl-high{color:var(--high)}.lvl-medium{color:var(--medium)}.lvl-low{color:var(--low)}
.matrix{table-layout:fixed}.matrix td{height:34px;font:700 14px var(--mono);border:1px solid var(--bg)}.matrix td,.matrix th{text-align:center;padding:6px}td b{white-space:nowrap}.matrix th{font-size:11px}
.m-low{background:rgba(43,98,168,.16)}.m-medium{background:rgba(154,107,0,.24)}
.m-high{background:rgba(200,80,30,.30)}.m-critical{background:rgba(163,18,42,.42)}
.mini td{padding:2px 6px;font-size:12px}.reasons{margin:4px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
details{margin:8px 0}summary{cursor:pointer;color:var(--muted)}
.kev{font:700 11.5px var(--mono);padding:1px 6px;white-space:nowrap;background:var(--critical);color:#fff}
.st{font:12px var(--mono);padding:1px 6px;border:1px dashed var(--line)}.st-acceptance-expired,.st-overdue{color:var(--high);font-weight:600}.st-accepted,.st-done{color:var(--low)}
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


def _owasp_html(r: Risk) -> str:
    if not r.owasp:
        return ""
    rows = "".join(f"<tr><td>{_e(k.replace('_', ' '))}</td><td>{v}</td><td class='muted'>{_e(r.owasp.why.get(k, ''))}</td></tr>" for k, v in r.owasp.factors.items())
    return (f"<br><span class='muted'>OWASP Risk Rating: <b>{_e(r.owasp.short())}</b></span>"
            f"<details><summary>OWASP factors</summary><table class='mini'>{rows}</table></details>")  # fmt: skip


def _threat_html(r: Risk) -> str:
    t = r.threat
    if not threat_line(r):
        return ""
    bits = []
    ids = t.cve or t.advisories
    if ids:
        bits.append("<b>" + _e(", ".join(ids[:5])) + "</b>")
    if t.cwe:
        bits.append(_e(", ".join(t.cwe)))
    bits += [_e(o) for o in t.owasp]
    if t.stride:
        bits.append("STRIDE: " + _e(", ".join(t.stride)))
    attack = ", ".join(f"<abbr title='{_e(a['tactic'])}'>{_e(a['id'])}</abbr> {_e(a['name'])}" for a in t.attack)
    html = "<br><span class='muted'>Threat: " + " &middot; ".join(bits) + (f"<br>ATT&amp;CK: {attack}" if attack else "") + (" <i>(by kind: the tool gave no CWE)</i>" if t.basis == "kind" else "") + "</span>"
    return html


def to_html(ctx: Context, risks: list[Risk], sources: list[Source], plan: Plan | None = None, intel: Intel | None = None) -> str:
    c = counts(risks)
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = bars([(n, c.get(n, 0), n) for n in ORDER])
    warn = ""
    gaps = gaps_of(sources) + intel_gaps(intel)
    if gaps:
        warn += '<div class="warn">Some checks did not run, so this register may be incomplete:<ul>' + "".join(f"<li>{_e(g)}</li>" for g in gaps) + "</ul></div>"
    warn += "".join(f'<div class="warn">{_e(n)}</div>' for n in notes_of(sources))
    warn += "".join(f'<div class="warn">{_e(w)}</div>' for w in plan_warnings(plan))
    rows = []
    for r in risks:
        reasons = "".join(f"<li>{_e(x)}</li>" for x in r.reasons)
        rows.append(
            f'<tr><td><b>{_e(r.id)}</b></td><td class="sev lvl-{r.level}">{_e(r.level)}<br>{r.score}<br>'
            f'<span class="muted">L{r.likelihood} x I{r.impact}</span></td>'
            f"<td><b>{_e(r.title)}</b>{(' <span class=kev>' + _e(kev_mark(r)) + '</span>') if kev_mark(r) else ''}<br><span class='muted'>{_e(r.kind)} &middot; {_e(', '.join(r.tools))} &middot; {_e(r.rule)} &middot; {r.count} occurrence(s)</span>"
            f"<br><code>{_e(', '.join(r.where))}</code>{_threat_html(r)}{_owasp_html(r)}<details><summary>why this score</summary><ul class='reasons'>{reasons}</ul></details></td>"
            f"<td>{_e(r.mitigation)}<br><span class='muted'>Suggested: {_e(r.target)}</span>"
            f"<br><span class='st st-{_e(r.state)}'>{_e(treatment_text(r) or STATE_LABEL['untreated'])}</span></td></tr>"
        )
    table = (
        '<div class="wrap"><table class="f"><tr><th>ID</th><th>Risk level</th><th>Risk</th><th>What to do</th></tr>' + "".join(rows) + "</table></div>"
        if rows else '<p class="muted">No risks in the reports.</p>'
    )
    method = "".join(f"<li>{_e(m)}</li>" for m in method_lines())
    targets = "".join(f"<li><b>{n}</b> ({LEVEL_UPPER[n]} or less): {_e(TARGETS[n])}</li>" for n in LEVELS)
    sources_html = "<br>".join(_e(s.path) for s in sources)
    treat = ""
    if plan:
        st = states(risks)
        treat = "<h2>Risk treatment</h2><p>" + " &middot; ".join(f"{_e(STATE_LABEL[k])}: <b>{st[k]}</b>" for k in STATE_LABEL if st.get(k)) + f"</p><p class='muted'>Decisions from {_e(plan.path)}. Accepted risks stay in the register; they no longer fail the build until the acceptance expires.</p>"
        fps = false_positive_lines(plan)
        if fps:
            treat += f"<details><summary>{len(fps)} finding(s) marked as false positive (left out of the register)</summary><ul>" + "".join(f"<li>{_e(x)}</li>" for x in fps) + "</ul></details>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>polyscan risk assessment</title><style>{CSS}{RISK_CSS}</style></head>
<body><main>
<p class="prompt">polyscan risk --exposure {_e(ctx.exposure)} --data {_e(ctx.data)}</p>
<h1>Risk assessment</h1>
<p class="sub">{_e(when)} &middot; polyscan {_e(__version__)}<br>Exposure: {_e(ctx.exposure)} ({_e(EXPOSURES[ctx.exposure][1])})<br>Data: {_e(ctx.data)} ({_e(DATA[ctx.data][1])})<br>From: {sources_html}{('<br>Threat intelligence: ' + _e('; '.join(intel.sources))) if intel and intel.sources else ''}</p>
{cards}{warn}
<h2>Risk matrix</h2>{_matrix_html(risks)}
<h2>Risk register</h2>{table}{treat}
<h2>How the score is computed</h2><ul>{method}</ul>
<h2>Suggested response times</h2><ul>{targets}</ul>
</main></body></html>
"""
