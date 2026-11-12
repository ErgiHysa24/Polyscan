"""History: how the findings of one project changed over several scans.

    polyscan history reports/*.json [--html FILE] [--markdown FILE] [--json FILE]

Reports are put in order by the time written inside them (`generated`); a report from an older
polyscan without that field uses the file's modification time, and the table says so. For each scan:
findings by severity, how many are new and how many were fixed since the scan before (same rules as
`polyscan diff`: a finding that disappeared because its tool did not run is "not verified", never
"fixed"), and how many checks did not run. An incomplete scan is marked: a drop in findings on that
row may only mean that less was checked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .diff import compare
from .models import Severity
from .report import CSS, _clean, _e, _md
from .risk import Source

ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class Point:
    source: Source
    when: str  # ISO time used for ordering
    from_file_time: bool
    counts: dict[str, int]
    gaps: int
    new: int | None = None
    fixed: int | None = None
    not_verified: int | None = None

    def to_dict(self) -> dict:
        return {
            "file": self.source.path, "when": self.when, "time_from_file": self.from_file_time, "findings": sum(self.counts.values()),
            "by_severity": self.counts, "checks_not_run": self.gaps, "new": self.new, "fixed": self.fixed, "not_verified": self.not_verified,
        }  # fmt: skip


def build(sources: list[Source]) -> list[Point]:
    points = []
    for s in sources:
        when, from_file = s.generated, False
        if not when:
            try:
                when = datetime.fromtimestamp(Path(s.path).stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except OSError:
                when = "0000-00-00T00:00:00Z"
            from_file = True
        counts = {sev.label: sum(f.severity == sev for f in s.findings) for sev in ORDER}
        points.append(Point(s, when, from_file, counts, len(s.gaps)))
    points.sort(key=lambda p: (p.when, p.source.path))
    for before, after in zip(points, points[1:]):
        c = compare(before.source, after.source).counts()
        after.new, after.fixed, after.not_verified = c["new"], c["fixed"], c["not_verified"]
    return points


def to_json(points: list[Point]) -> str:
    return json.dumps({"polyscan": __version__, "kind": "history", "scans": [p.to_dict() for p in points]}, indent=2)


def _delta(p: Point) -> str:
    if p.new is None:
        return "first scan"
    return f"+{p.new} new, -{p.fixed} fixed" + (f", {p.not_verified} not verified" if p.not_verified else "")


def to_terminal(points: list[Point]) -> str:
    out = ["polyscan history", "", f"{'when (UTC)':20} {'crit':>5} {'high':>5} {'med':>5} {'low':>5} {'info':>5}  change"]
    for p in points:
        c = p.counts
        flag = f"  INCOMPLETE: {p.gaps} check(s) did not run" if p.gaps else ""
        when = p.when.replace("T", " ").rstrip("Z") + ("*" if p.from_file_time else "")
        out.append(f"{when:20} {c['critical']:>5} {c['high']:>5} {c['medium']:>5} {c['low']:>5} {c['info']:>5}  {_delta(p)}{flag}  [{_clean(p.source.path)}]")
    if any(p.from_file_time for p in points):
        out.append("* time taken from the file (the report has no 'generated' field)")
    return "\n".join(out) + "\n"


def to_markdown(points: list[Point]) -> str:
    lines = ["## Scan history", "", "| When (UTC) | Critical | High | Medium | Low | Info | Change | Checks not run | Report |", "|---|---|---|---|---|---|---|---|---|"]
    for p in points:
        c = p.counts
        when = p.when.replace("T", " ").rstrip("Z") + (" \\*" if p.from_file_time else "")
        lines.append(f"| {when} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} | {_delta(p)} | {p.gaps or ''} | {_md(p.source.path, 80)} |")
    return "\n".join(lines) + "\n"


def _chart(points: list[Point]) -> str:
    """Stacked bars, one per scan, drawn as inline SVG (no script, no external file)."""
    if not points:
        return ""
    top = max(sum(p.counts.values()) for p in points) or 1
    w, h, gap = 46, 160, 14
    colors = {"critical": "var(--critical)", "high": "var(--high)", "medium": "var(--medium)", "low": "var(--low)", "info": "var(--info)"}
    bars = []
    for i, p in enumerate(points):
        x, y = i * (w + gap), h
        for name in ("info", "low", "medium", "high", "critical"):
            height = p.counts[name] / top * h
            y -= height
            if height:
                bars.append(f'<rect x="{x}" y="{y:.1f}" width="{w}" height="{height:.1f}" fill="{colors[name]}"><title>{p.counts[name]} {name}</title></rect>')
        if p.gaps:
            bars.append(f'<text x="{x + w / 2}" y="{h + 28}" text-anchor="middle" font-size="10" fill="var(--bad)">incomplete</text>')
        bars.append(f'<text x="{x + w / 2}" y="{h + 14}" text-anchor="middle" font-size="10" fill="var(--muted)">{_e(p.when[5:10])}</text>')
    width = len(points) * (w + gap)
    return f'<div class="wrap"><svg role="img" aria-label="findings per scan" viewBox="0 0 {width} {h + 32}" width="{min(width, 900)}" height="{h + 32}">{"".join(bars)}</svg></div>'


def to_html(points: list[Point]) -> str:
    rows = "".join(
        f"<tr><td>{_e(p.when.replace('T', ' ').rstrip('Z'))}{'*' if p.from_file_time else ''}</td>"
        + "".join(f"<td class='{n}'>{p.counts[n] or ''}</td>" for n in ("critical", "high", "medium", "low", "info"))
        + f"<td>{_e(_delta(p))}</td><td class='{'bad' if p.gaps else ''}'>{p.gaps or ''}</td><td><code>{_e(p.source.path)}</code></td></tr>"
        for p in points
    )
    note = "<p class='muted'>* time taken from the file: the report has no 'generated' field.</p>" if any(p.from_file_time for p in points) else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>polyscan history</title><style>{CSS}.bad{{color:var(--bad);font-weight:600}}</style></head>
<body><main>
<h1>Scan history</h1><p class="sub">{len(points)} scans &middot; polyscan {_e(__version__)}</p>
{_chart(points)}
<div class="wrap"><table class="f"><tr><th>When (UTC)</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Change since the scan before</th><th>Checks not run</th><th>Report</th></tr>{rows}</table></div>
{note}<p class="muted">A finding that disappeared counts as fixed only if its tool ran correctly in the later scan. On a row with checks not run, fewer findings may only mean that less was checked.</p>
</main></body></html>
"""
