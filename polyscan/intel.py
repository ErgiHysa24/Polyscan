"""Threat intelligence for the CVEs in the register: is it being exploited NOW (CISA KEV), and how likely
is exploitation in the next 30 days (FIRST EPSS)?

CVSS (the tool's severity) says how bad a vulnerability is *if* it is exploited. It says nothing about
whether anyone is doing it. Two public, free sources answer that:

  * **CISA KEV** (Known Exploited Vulnerabilities): a catalog of CVEs with evidence of exploitation in the
    wild, kept by the US Cybersecurity and Infrastructure Security Agency.
  * **EPSS** (Exploit Prediction Scoring System, by FIRST): for every CVE, the probability (0-1) that it
    will be exploited in the next 30 days, and its percentile among all CVEs.

How polyscan uses them (a choice, written here and in every report):
  * a CVE in KEV sets the likelihood of its risk to 5: exploitation is a fact, not a guess;
  * otherwise an EPSS probability of 10% or more adds 1 to the likelihood (10% is a common
    threshold; FIRST suggests each organisation picks its own);
  * nothing lowers a likelihood: a low EPSS is not proof of safety.

Network use is opt-in (`polyscan risk --intel`). For a machine without internet, or to make a report
reproducible, the same data can be given as files (`--kev-file`, `--epss-file`). A source that could
not be read is reported as a gap: the register then says it is incomplete instead of looking calm.
"""

from __future__ import annotations

import csv
import io
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's own mirror on GitHub, used when the first one is unreachable
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_THRESHOLD = 0.10
EPSS_BATCH = 50
MAX_BYTES = 30 * 1024 * 1024
TIMEOUT = 30
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class Intel:
    kev: dict[str, dict] = field(default_factory=dict)  # CVE -> {"dateAdded", "dueDate", "ransomware", "name"}
    epss: dict[str, dict] = field(default_factory=dict)  # CVE -> {"epss": float, "percentile": float, "date": str}
    sources: list[str] = field(default_factory=list)  # what was read, for the report
    problems: list[str] = field(default_factory=list)  # what could NOT be read: a coverage gap

    def to_dict(self) -> dict:
        return {"sources": self.sources, "problems": self.problems, "kev_entries": len(self.kev), "epss_scores": len(self.epss),
                "epss_threshold": EPSS_THRESHOLD}  # fmt: skip


def _get(url: str, opener=urllib.request.urlopen) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "polyscan", "Accept": "application/json, text/csv"})
    with opener(req, timeout=TIMEOUT) as resp:  # noqa: S310 - fixed https URLs only
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response too large")
    return data


# ------------------------------------------------------------------ KEV
def parse_kev(data) -> dict[str, dict]:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("not a CISA KEV catalog (no 'vulnerabilities' list)")
    out = {}
    for v in data["vulnerabilities"]:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID", "")).strip().upper()
        if CVE.match(cve):
            out[cve] = {
                "dateAdded": str(v.get("dateAdded", ""))[:10], "dueDate": str(v.get("dueDate", ""))[:10],
                "ransomware": str(v.get("knownRansomwareCampaignUse", "Unknown"))[:20],
                "name": " ".join(str(v.get("vulnerabilityName", "")).split())[:200],
            }  # fmt: skip
    if not out:
        raise ValueError("the KEV catalog has no CVE in it")
    return out


def kev_from_file(path: str) -> tuple[dict[str, dict], str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_kev(data), f"CISA KEV from {path} (catalog {data.get('catalogVersion', '?')})"


def kev_download(get=_get) -> tuple[dict[str, dict], str]:
    errors = []
    for url in KEV_URLS:
        try:
            data = json.loads(get(url))
            return parse_kev(data), f"CISA KEV {data.get('catalogVersion', '?')} from {url}"
        except Exception as exc:  # noqa: BLE001 - every failure is reported, then the next mirror is tried
            errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:120]}")
    raise ValueError("could not read the CISA KEV catalog: " + " | ".join(errors))


# ------------------------------------------------------------------ EPSS
def _score(row: dict) -> dict | None:
    cve = str(row.get("cve", "")).strip().upper()
    try:
        epss, pct = float(row.get("epss")), float(row.get("percentile"))
    except (TypeError, ValueError):
        return None
    if not CVE.match(cve) or not (0 <= epss <= 1 and 0 <= pct <= 1):
        return None
    return {"cve": cve, "epss": epss, "percentile": pct, "date": str(row.get("date", ""))[:10]}


def parse_epss(text: str) -> dict[str, dict]:
    """The API's JSON ({"data": [{"cve", "epss", "percentile", "date"}]}) or FIRST's daily CSV
    (a '#model_version...' comment line, then 'cve,epss,percentile')."""
    text = text.lstrip("﻿")
    rows: list = []
    if text.lstrip().startswith("{"):
        data = json.loads(text)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise ValueError("not an EPSS API response (no 'data' list)")
        rows = data["data"]
    else:
        date = ""
        lines = text.splitlines()
        if lines and lines[0].startswith("#"):
            m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", lines[0])
            date = m.group(1) if m else ""
            lines = lines[1:]
        rows = [{**r, "date": date} for r in csv.DictReader(io.StringIO("\n".join(lines)))]
    out = {}
    for row in rows:
        s = _score(row) if isinstance(row, dict) else None
        if s:
            out[s.pop("cve")] = s
    return out


def epss_download(cves: list[str], get=_get) -> tuple[dict[str, dict], str]:
    wanted = sorted({c for c in cves if CVE.match(c)})
    out: dict[str, dict] = {}
    for i in range(0, len(wanted), EPSS_BATCH):
        batch = wanted[i : i + EPSS_BATCH]
        url = f"{EPSS_API}?{urllib.parse.urlencode({'cve': ','.join(batch), 'limit': len(batch)})}"
        text = get(url).decode("utf-8", errors="replace")
        data = json.loads(text)
        if str(data.get("status", "OK")).upper() != "OK":
            raise ValueError(f"EPSS API answered {str(data.get('status'))[:40]}")
        out.update(parse_epss(text))
    return out, f"FIRST EPSS API ({len(out)} of {len(wanted)} CVEs scored)"


# ------------------------------------------------------------------ putting it together
def gather(cves: list[str], download: bool, kev_file: str | None = None, epss_file: str | None = None, get=_get) -> Intel:
    intel = Intel()
    try:
        if kev_file:
            intel.kev, src = kev_from_file(kev_file)
            intel.sources.append(src)
        elif download:
            intel.kev, src = kev_download(get)
            intel.sources.append(src)
    except (OSError, ValueError) as exc:
        intel.problems.append(f"KEV: {str(exc)[:300]}")
    try:
        if epss_file:
            intel.epss = parse_epss(Path(epss_file).read_text(encoding="utf-8"))
            intel.sources.append(f"EPSS from {epss_file} ({len(intel.epss)} scores)")
        elif download and cves:
            intel.epss, src = epss_download(cves, get)
            intel.sources.append(src)
    except Exception as exc:  # noqa: BLE001 - reported as a gap, never silently ignored
        intel.problems.append(f"EPSS: {type(exc).__name__}: {str(exc)[:300]}")
    return intel


def adjust(cves: list[str], likelihood: int, intel: Intel | None) -> tuple[int, list[str], dict]:
    """New likelihood, the reasons, and what was found (for the report)."""
    if not intel or not cves:
        return likelihood, [], {}
    kev = {c: intel.kev[c] for c in cves if c in intel.kev}
    scores = {c: intel.epss[c] for c in cves if c in intel.epss}
    found = {"kev": kev, "epss": scores}
    reasons = []
    if kev:
        first = sorted(kev)[0]
        e = kev[first]
        extra = ", used in ransomware campaigns" if e["ransomware"].lower() == "known" else ""
        reasons.append(f"Likelihood set to 5: {first} is in CISA KEV (exploited in the wild, listed {e['dateAdded']}{extra}).")
        return 5, reasons, found
    if scores:
        best = max(scores, key=lambda c: scores[c]["epss"])
        s = scores[best]
        if s["epss"] >= EPSS_THRESHOLD:
            new = min(5, likelihood + 1)
            reasons.append(
                f"Likelihood +1: EPSS gives {best} a {s['epss']:.1%} chance of exploitation in the next 30 days "
                f"(percentile {s['percentile']:.0%}, threshold {EPSS_THRESHOLD:.0%})."
            )
            return new, reasons, found
        reasons.append(f"EPSS for {best} is {s['epss']:.2%} (below {EPSS_THRESHOLD:.0%}): likelihood unchanged.")
    return likelihood, reasons, found
