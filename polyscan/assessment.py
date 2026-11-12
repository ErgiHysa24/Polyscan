"""The assessment report: one printable HTML document that puts a whole assessment together, in the
order a vulnerability assessment report is usually read (NIST SP 800-115 "reporting" phase, PTES and
OWASP WSTG reporting guidance):

  1. scope and authorization   - what was tested, by whom, with whose permission, what was NOT tested
  2. executive summary         - for a reader who will not read further
  3. method and coverage       - every check, whether it ran, and what it looks for
  4. risk matrix and register  - likelihood x impact, with the reasons
  5. risk treatment            - the decisions taken (when a decisions file is given)
  6. threats                   - MITRE ATT&CK techniques by tactic, OWASP Top 10 categories
  7. retest                    - what was fixed (when an earlier report is given)
  8. appendix                  - scoring method and sources

    polyscan report scan.json [dast.json ports.json] --title "..." --target "..." --tester "..." \\
        --authorized-by "..." [--decisions FILE] [--intel] [--retest BEFORE.json] --html report.html

Everything that came from scanned code or from a report file is escaped (and the page has a strict
CSP), like every other polyscan report. The page prints well (browser "Save as PDF").
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .diff import GROUPS as DIFF_GROUPS
from .diff import LABEL as DIFF_LABEL
from .diff import Diff
from .intel import Intel
from .report import CSS, _e
from .risk import DATA, EXPOSURES, LEVEL_UPPER, LEVELS, TARGETS, Context, Risk, Source
from .riskreport import (
    RISK_CSS,
    _owasp_html,
    STATE_LABEL,
    _matrix_html,
    _threat_html,
    false_positive_lines,
    gaps_of,
    intel_gaps,
    kev_mark,
    method_lines,
    notes_of,
    plan_warnings,
    states,
    treatment_text,
)
from .treatment import Plan

ORDER = list(reversed(LEVELS))

# What each check looks for, for the "method and coverage" table (kept short and factual).
CHECKS = {
    "semgrep": ("Static analysis (SAST)", "Insecure code patterns: injection, XSS, weak crypto, unsafe APIs (OWASP / security-audit rules and polyscan's SQL rules)"),
    "gitleaks": ("Secrets", "Passwords, API keys and tokens in the files"),
    "gitleaks-history": ("Secrets", "The same, in every commit of the git history"),
    "osv-scanner": ("Dependencies (SCA)", "Known vulnerabilities (OSV database) in the libraries of every lockfile"),
    "bandit": ("Static analysis (SAST)", "Python-specific security issues"),
    "npm-audit": ("Dependencies (SCA)", "npm advisories for package-lock.json"),
    "cargo-audit": ("Dependencies (SCA)", "RustSec advisories for Cargo.lock"),
    "composer-audit": ("Dependencies (SCA)", "Packagist advisories and abandoned packages for composer.lock"),
    "progpilot": ("Static analysis (SAST)", "PHP taint analysis: untrusted input reaching SQL, shell, eval, output"),
    "spotbugs": ("Static analysis (SAST)", "Java bytecode, Find Security Bugs rules (injection, crypto, deserialization)"),
    "trivy": ("Container images", "Known vulnerabilities (HIGH, CRITICAL) in the Docker images named in the project"),
    "checkov": ("Configuration (IaC)", "Dockerfile, docker-compose, Kubernetes and Terraform misconfigurations"),
    "zap": ("Running application (DAST)", "Passive scan of the live site: headers, cookies, information leaks, forms (no attacks sent)"),
    "ss": ("Host network", "Listening TCP/UDP ports of this machine and who can reach them"),
}
NOT_TESTED = [
    "No active attacks were sent (no exploitation, no fuzzing, no brute force): the live-site check is passive.",
    "Login forms are not filled in; only pages reachable with the given token or cookie were seen.",
    "Business logic, authorization between users and race conditions need a manual test.",
    "The firewall in front of the host is not seen: an open port may still be filtered from outside.",
]


@dataclass
class Meta:
    title: str = "Security assessment"
    target: str = ""
    tester: str = ""
    authorized_by: str = ""
    period: str = ""
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)


def _list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{_e(x)}</li>" for x in items) + "</ul>" if items else ""


def tools_of(sources: list[Source]) -> list[dict]:
    seen: dict[str, dict] = {}
    for s in sources:
        for t in s.tools:
            name = str(t.get("name", "?"))
            # the same tool in two reports: keep the worst status, so a failure is never hidden
            rank = {"error": 3, "unavailable": 2, "skipped": 1, "ok": 0}
            if name not in seen or rank.get(str(t.get("status")), 0) > rank.get(str(seen[name].get("status")), 0):
                seen[name] = {**t, "report": s.path}
    return list(seen.values())


def attack_by_tactic(risks: list[Risk]) -> dict[str, list[tuple[str, str, int]]]:
    """tactic -> [(technique id, name, number of active risks)], from the active risks."""
    count: Counter = Counter()
    names, tactics = {}, {}
    for r in risks:
        if not r.active or not r.threat:
            continue
        for a in r.threat.attack:
            count[a["id"]] += 1
            names[a["id"]] = a["name"]
            tactics[a["id"]] = a["tactic"].split(" / ")[0]
    out: dict[str, list] = {}
    for tid, n in count.most_common():
        out.setdefault(tactics[tid], []).append((tid, names[tid], n))
    return out


def owasp_counts(risks: list[Risk]) -> Counter:
    return Counter(o for r in risks if r.active and r.threat for o in r.threat.owasp)


def executive_summary(risks: list[Risk], sources: list[Source], plan: Plan | None, intel: Intel | None) -> list[str]:
    active = [r for r in risks if r.active]
    c = Counter(r.level for r in active)
    out = []
    if not risks:
        out.append("No risks were found in the reports.")
    else:
        parts = ", ".join(f"{c[n]} {n}" for n in ORDER if c.get(n))
        out.append(f"{len(active)} open risk(s) ({parts or 'none'}) from {sum(r.count for r in risks)} finding(s).")
    kev = [r for r in active if r.intel.get("kev")]
    if kev:
        out.append(f"{len(kev)} open risk(s) concern vulnerabilities that are exploited in the wild (CISA KEV): fix these first.")
    urgent = [r for r in active if r.level in ("critical", "high")]
    if urgent:
        out.append(f"{len(urgent)} critical/high risk(s): suggested response {TARGETS['critical']} for critical, {TARGETS['high']} for high.")
    if plan:
        st = states(risks)
        out.append(
            f"Treatment: {st.get('accepted', 0)} accepted, {st.get('planned', 0)} planned, {st.get('overdue', 0)} overdue, "
            f"{st.get('acceptance-expired', 0)} expired acceptance(s), {st.get('untreated', 0)} without a decision; "
            f"{len(plan.false_positives)} finding(s) dismissed as false positive."
        )
    gaps = gaps_of(sources) + intel_gaps(intel)
    if gaps:
        out.append(f"{len(gaps)} check(s) did not run: the assessment is INCOMPLETE for what they cover (see 'Method and coverage').")
    return out


REPORT_CSS = """
.cover{border-bottom:3px solid var(--text);padding:8px 0 18px;margin-bottom:22px}
.cover h1{font-size:28px}.kv{display:grid;grid-template-columns:180px 1fr;gap:4px 14px;margin:12px 0}
.kv b{color:var(--muted);font-weight:600}.exec li{margin:4px 0}.toc{columns:2;font-size:14px}
.ok{color:var(--low)}.bad{color:var(--bad);font-weight:600}
@media print{body{background:#fff}main{max-width:none}.card,table{break-inside:avoid}h2{break-before:auto}
details{display:block}details>summary{display:none}a{color:inherit}}
"""


def to_html(meta: Meta, ctx: Context, risks: list[Risk], sources: list[Source], plan: Plan | None = None,
            intel: Intel | None = None, retest: Diff | None = None) -> str:  # fmt: skip
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    active = [r for r in risks if r.active]
    c = Counter(r.level for r in active)
    cards = "".join(f'<div class="card"><b class="lvl-{n}">{c.get(n, 0)}</b><span>{n} (open)</span></div>' for n in ORDER)

    # 1 scope
    kv = [("Target", meta.target), ("Assessor", meta.tester), ("Authorized by", meta.authorized_by), ("Period", meta.period),
          ("Exposure", f"{ctx.exposure} - {EXPOSURES[ctx.exposure][1]}"), ("Data", f"{ctx.data} - {DATA[ctx.data][1]}"),
          ("Generated", f"{when}, polyscan {__version__}")]  # fmt: skip
    kv_html = "".join(f"<b>{_e(k)}</b><span>{_e(v)}</span>" for k, v in kv if v)
    no_auth = "" if meta.authorized_by else '<div class="warn">No authorization is recorded in this report (--authorized-by). Testing a system you do not own requires written permission.</div>'
    scope = (
        f"<h2>1. Scope and authorization</h2><div class='kv'>{kv_html}</div>{no_auth}"
        + (f"<p><b>In scope</b></p>{_list(meta.scope)}" if meta.scope else "")
        + f"<p><b>Not tested</b></p>{_list(meta.out_of_scope + NOT_TESTED)}"
        + "<p class='muted'>Reports read: " + ", ".join(_e(s.path) for s in sources) + "</p>"
    )

    # 2 executive summary
    top = "".join(
        f"<tr><td><b>{_e(r.id)}</b></td><td class='lvl-{r.level}'>{_e(r.level)} {r.score}</td><td>{_e(r.title)}"
        f"{(' <span class=kev>' + _e(kev_mark(r)) + '</span>') if kev_mark(r) else ''}</td><td>{_e(r.target)}</td></tr>"
        for r in active[:5]
    )
    exec_html = (
        f"<h2>2. Executive summary</h2><div class='cards'>{cards}</div><ul class='exec'>"
        + "".join(f"<li>{_e(x)}</li>" for x in executive_summary(risks, sources, plan, intel)) + "</ul>"
        + (f"<p><b>Top risks</b></p><div class='wrap'><table><tr><th>ID</th><th>Level</th><th>Risk</th><th>Respond</th></tr>{top}</table></div>" if top else "")
    )  # fmt: skip

    # 3 method and coverage
    rows = []
    for t in tools_of(sources):
        name, status = str(t.get("name")), str(t.get("status"))
        area, what = CHECKS.get(name, ("Other", ""))
        css = "ok" if status == "ok" else ("muted" if status == "skipped" else "bad")
        detail = str(t.get("detail", ""))[:200]
        rows.append(f"<tr><td><b>{_e(name)}</b></td><td>{_e(area)}</td><td>{_e(what)}</td><td class='{css}'>{_e(status)}"
                    f"{('<br><span class=muted>' + _e(detail) + '</span>') if detail and status != 'ok' else ''}</td><td>{_e(t.get('findings', ''))}</td></tr>")  # fmt: skip
    gaps = gaps_of(sources) + intel_gaps(intel)
    method = (
        "<h2>3. Method and coverage</h2><p>Automated checks, each run with a fixed tool version (Docker images pinned by digest). "
        "A check that did not run is shown as such and is never counted as clean.</p>"
        + (f"<div class='warn'>Incomplete: {len(gaps)} check(s) did not run.{_list(gaps)}</div>" if gaps else "")
        + "<div class='wrap'><table class='f'><tr><th>Check</th><th>Area</th><th>What it looks for</th><th>Status</th><th>Findings</th></tr>"
        + "".join(rows) + "</table></div>"
        + (f"<p class='muted'>Threat intelligence: {_e('; '.join(intel.sources))}</p>" if intel and intel.sources else "")
        + "".join(f"<div class='warn'>{_e(n)}</div>" for n in notes_of(sources))
    )  # fmt: skip

    # 4 register
    reg_rows = []
    for r in risks:
        reasons = "".join(f"<li>{_e(x)}</li>" for x in r.reasons)
        reg_rows.append(
            f"<tr><td><b>{_e(r.id)}</b></td><td class='sev lvl-{r.level}'>{_e(r.level)}<br>{r.score}<br><span class='muted'>L{r.likelihood} x I{r.impact}</span></td>"
            f"<td><b>{_e(r.title)}</b>{(' <span class=kev>' + _e(kev_mark(r)) + '</span>') if kev_mark(r) else ''}<br><span class='muted'>{_e(r.kind)} &middot; {_e(', '.join(r.tools))} &middot; {_e(r.rule)} &middot; {r.count}x</span>"
            f"<br><code>{_e(', '.join(r.where))}</code>{_threat_html(r)}{_owasp_html(r)}<details><summary>why this score</summary><ul class='reasons'>{reasons}</ul></details></td>"
            f"<td>{_e(r.mitigation)}<br><span class='muted'>Respond: {_e(r.target)}</span><br><span class='st st-{_e(r.state)}'>{_e(treatment_text(r) or STATE_LABEL['untreated'])}</span></td></tr>"
        )  # fmt: skip
    # polyscan level vs OWASP severity: where the two methods agree and where they do not
    owasp_levels = ["Critical", "High", "Medium", "Low", "Note"]
    cross = Counter((r.level, r.owasp.severity) for r in risks if r.owasp)
    cross_rows = "".join(
        f"<tr><th>{_e(lv)}</th>" + "".join(f"<td>{cross.get((lv, ow), '') or ''}</td>" for ow in owasp_levels) + "</tr>" for lv in ORDER
    )
    compare = (
        "<p><b>Second opinion: OWASP Risk Rating Methodology</b> (rows: polyscan level, columns: OWASP severity). "
        "Cells off the diagonal are where the two methods disagree: read the factors of those risks.</p>"
        f"<div class='wrap'><table class='matrix'><tr><th></th>" + "".join(f"<th>{o}</th>" for o in owasp_levels) + f"</tr>{cross_rows}</table></div>"
    ) if cross else ""
    register = (
        f"<h2>4. Risk matrix and register</h2>{_matrix_html(risks)}{compare}"
        + ("<div class='wrap'><table class='f'><tr><th>ID</th><th>Level</th><th>Risk</th><th>Response</th></tr>" + "".join(reg_rows) + "</table></div>"
           if reg_rows else "<p class='muted'>No risks.</p>")
    )  # fmt: skip

    # 5 treatment
    treat = ""
    if plan:
        st = states(risks)
        fps = false_positive_lines(plan)
        treat = (
            "<h2>5. Risk treatment</h2><p>" + " &middot; ".join(f"{_e(STATE_LABEL[k])}: <b>{st[k]}</b>" for k in STATE_LABEL if st.get(k)) + "</p>"
            + f"<p class='muted'>Decisions from {_e(plan.path)}. Accepted risks stay in the register and stop failing the build until the acceptance expires; "
            "a treatment marked done that the scan still finds is not counted as treated.</p>"
            + "".join(f"<div class='warn'>{_e(w)}</div>" for w in plan_warnings(plan))
            + (f"<p><b>Dismissed as false positive ({len(fps)})</b></p>{_list(fps)}" if fps else "")
        )  # fmt: skip

    # 6 threats
    tactics = attack_by_tactic(risks)
    t_rows = "".join(
        f"<tr><td>{_e(tactic)}</td><td>" + "<br>".join(f"<b>{_e(tid)}</b> {_e(name)} <span class='muted'>({n} risk(s))</span>" for tid, name, n in items) + "</td></tr>"
        for tactic, items in tactics.items()
    )  # fmt: skip
    ow = owasp_counts(risks)
    threats = (
        "<h2>6. Threats</h2><p>MITRE ATT&amp;CK techniques that the open risks would make possible, grouped by tactic "
        "(links from CWE and kind of finding: polyscan's own mapping, see the appendix).</p>"
        + (f"<div class='wrap'><table><tr><th>Tactic</th><th>Techniques</th></tr>{t_rows}</table></div>" if t_rows else "<p class='muted'>No technique linked.</p>")
        + (("<p><b>OWASP Top 10 (2021)</b></p><ul>" + "".join(f"<li>{_e(o)}: {n} risk(s)</li>" for o, n in sorted(ow.items())) + "</ul>") if ow else "")
    )  # fmt: skip

    # 7 retest
    retest_html = ""
    if retest:
        rc = retest.counts()
        rows = "".join(f"<div class='card'><b>{rc[g]}</b><span>{_e(DIFF_LABEL[g])}</span></div>" for g in DIFF_GROUPS)
        retest_html = (
            f"<h2>7. Retest</h2><p>Compared with {_e(retest.before.path)}. A finding that disappeared counts as fixed only if its tool ran correctly again.</p>"
            f"<div class='cards'>{rows}</div>"
            + (f"<div class='warn'>Not verified: {rc['not_verified']} finding(s) disappeared because their tool did not run.</div>" if rc["not_verified"] else "")
        )  # fmt: skip

    # 8 appendix
    targets = "".join(f"<li><b>{n}</b> (score {LEVEL_UPPER[n]} or less): {_e(TARGETS[n])}</li>" for n in LEVELS)
    appendix = (
        "<h2>8. Appendix: scoring method</h2><ul>" + "".join(f"<li>{_e(m)}</li>" for m in method_lines()) + "</ul>"
        + f"<p><b>Suggested response times</b></p><ul>{targets}</ul>"
        + "<p class='muted'>References: NIST SP 800-30 Rev. 1 (risk assessment), NIST SP 800-115 (security testing), ISO/IEC 27005 (risk treatment), "
        "OWASP Top 10 2021, MITRE ATT&amp;CK Enterprise v20, CISA KEV, FIRST EPSS, OASIS SARIF 2.1.0.</p>"
    )  # fmt: skip

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{_e(meta.title)}</title><style>{CSS}{RISK_CSS}{REPORT_CSS}</style></head>
<body><main>
<div class="cover"><h1>{_e(meta.title)}</h1><p class="sub">{_e(meta.target or 'target not named')} &middot; {_e(when)}</p></div>
{scope}{exec_html}{method}{register}{treat}{threats}{retest_html}{appendix}
</main></body></html>
"""
