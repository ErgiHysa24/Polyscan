"""OWASP Risk Rating Methodology, as a second, independent rating of every risk.

The OWASP method (https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) scores 16 factors
from 0 to 9:

  likelihood = average of
    threat agent:   skill level, motive, opportunity, size
    vulnerability:  ease of discovery, ease of exploit, awareness, intrusion detection
  impact = average of the BUSINESS factors (financial damage, reputation damage, non-compliance,
           privacy violation) when they are known, otherwise of the TECHNICAL factors (loss of
           confidentiality, integrity, availability, accountability)

  0 to <3 LOW, 3 to <6 MEDIUM, 6 to 9 HIGH, and the overall severity is

                     impact LOW   MEDIUM   HIGH
    likelihood HIGH    Medium     High     Critical
               MEDIUM  Low        Medium   High
               LOW     Note       Low      Medium

Most factors describe the organisation, not the finding (who would attack, whether attacks are
logged, what a breach would cost), so they cannot come from a scanner. polyscan therefore:

  * takes the threat-agent factors from the context (--exposure, --data) unless a factors file says
    otherwise, and intrusion detection from the file (default 8: "logged without review");
  * derives the vulnerability factors from the finding: how it was found, whether its CVE is in
    CISA KEV or has a high EPSS, whether the advisory is public;
  * derives the technical impact from the STRIDE threats of the risk (I -> confidentiality,
    T -> integrity, D -> availability, S/R -> accountability) scaled by the tool's severity;
  * uses the business impact only when the factors file gives it.

Every derived value carries its reason, and a factors file can override any factor for a rule or
file. The defaults are polyscan's reading of the OWASP option tables, written below; change them
where your situation is different.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Severity

THREAT_AGENT = ("skill_level", "motive", "opportunity", "size")
VULNERABILITY = ("ease_of_discovery", "ease_of_exploit", "awareness", "intrusion_detection")
TECHNICAL = ("loss_of_confidentiality", "loss_of_integrity", "loss_of_availability", "loss_of_accountability")
BUSINESS = ("financial_damage", "reputation_damage", "non_compliance", "privacy_violation")
ALL = THREAT_AGENT + VULNERABILITY + TECHNICAL + BUSINESS

# threat agent from --exposure: who could reach the application
AGENT_BY_EXPOSURE = {
    #           skill  opportunity  size   (OWASP: size 9 = anonymous internet users, 4 = intranet, 2 = developers)
    "internet": (6, 7, 9),
    "internal": (5, 4, 4),
    "local": (5, 4, 2),
}
MOTIVE_BY_DATA = {"personal": 9, "internal": 4, "public": 1}  # OWASP: 1 low or no reward, 4 possible, 9 high
# vulnerability factors by kind of finding: (ease of discovery, ease of exploit, awareness)
VULN_BY_KIND = {
    "dependency": (9, 3, 9),  # public advisory: scanners find it (9), the advisory is public knowledge (9)
    "runtime": (9, 5, 6),  # seen from outside by an automated scanner, obvious to anyone who looks
    "secret": (7, 9, 4),  # easy to find once the code or history is readable; using a key needs no skill
    "code": (3, 3, 4),  # needs access to the source code; exploitation depends on the data flow
    "config": (3, 3, 4),
}
MAGNITUDE = {Severity.CRITICAL: 9, Severity.HIGH: 7, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 1}
SEVERITY_TABLE = {
    ("HIGH", "LOW"): "Medium", ("HIGH", "MEDIUM"): "High", ("HIGH", "HIGH"): "Critical",
    ("MEDIUM", "LOW"): "Low", ("MEDIUM", "MEDIUM"): "Medium", ("MEDIUM", "HIGH"): "High",
    ("LOW", "LOW"): "Note", ("LOW", "MEDIUM"): "Low", ("LOW", "HIGH"): "Medium",
}  # fmt: skip
DEFAULT_INTRUSION_DETECTION = 8


def band(value: float) -> str:
    return "LOW" if value < 3 else ("MEDIUM" if value < 6 else "HIGH")


@dataclass
class Override:
    rule: str = ""
    file: str = ""
    factors: dict[str, int] = field(default_factory=dict)

    def matches(self, rule: str, files: list[str]) -> bool:
        if self.rule and not fnmatch.fnmatchcase(rule, self.rule):
            return False
        return not self.file or any(fnmatch.fnmatchcase(f, self.file) for f in files)


@dataclass
class Factors:
    """What the organisation knows about itself (from the factors file)."""

    path: str = ""
    agent: dict[str, int] = field(default_factory=dict)
    intrusion_detection: int = DEFAULT_INTRUSION_DETECTION
    business: dict[str, int] = field(default_factory=dict)
    overrides: list[Override] = field(default_factory=list)


def _factor(value, name: str, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 9:
        raise ValueError(f"{where}: {name} must be a whole number from 0 to 9")
    return value


def parse(data, path: str = "factors") -> Factors:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f'{path}: expected {{"version": 1, ...}}')
    allowed = {"version", "threat_agent", "intrusion_detection", "business_impact", "overrides"}
    if set(data) - allowed:
        raise ValueError(f"{path}: unknown field(s) {sorted(set(data) - allowed)}")
    f = Factors(path)
    agent = data.get("threat_agent") or {}
    if not isinstance(agent, dict) or set(agent) - set(THREAT_AGENT):
        raise ValueError(f"{path}: threat_agent takes {list(THREAT_AGENT)}")
    f.agent = {k: _factor(v, k, path) for k, v in agent.items()}
    if "intrusion_detection" in data:
        f.intrusion_detection = _factor(data["intrusion_detection"], "intrusion_detection", path)
    business = data.get("business_impact") or {}
    if not isinstance(business, dict) or set(business) - set(BUSINESS):
        raise ValueError(f"{path}: business_impact takes {list(BUSINESS)}")
    if business and set(business) != set(BUSINESS):
        raise ValueError(f"{path}: give all four business factors {list(BUSINESS)} or none (OWASP averages them)")
    f.business = {k: _factor(v, k, path) for k, v in business.items()}
    for n, item in enumerate(data.get("overrides") or [], 1):
        where = f"{path}, override #{n}"
        if not isinstance(item, dict) or set(item) - {"rule", "file", "factors"}:
            raise ValueError(f"{where}: takes rule, file and factors")
        if not (item.get("rule") or item.get("file")):
            raise ValueError(f"{where}: give a rule or a file pattern")
        factors = item.get("factors")
        if not isinstance(factors, dict) or not factors or set(factors) - set(ALL):
            raise ValueError(f"{where}: factors must be some of {list(ALL)}")
        f.overrides.append(Override(str(item.get("rule", "")), str(item.get("file", "")),
                                    {k: _factor(v, k, where) for k, v in factors.items()}))  # fmt: skip
    return f


def load(path: str) -> Factors:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot read the file ({exc.strerror or exc})") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON (line {exc.lineno})") from None
    return parse(data, path)


@dataclass
class Rating:
    factors: dict[str, int]
    why: dict[str, str]
    likelihood: float
    impact: float
    impact_basis: str  # "business" | "technical"

    @property
    def likelihood_level(self) -> str:
        return band(self.likelihood)

    @property
    def impact_level(self) -> str:
        return band(self.impact)

    @property
    def severity(self) -> str:
        return SEVERITY_TABLE[(self.likelihood_level, self.impact_level)]

    def to_dict(self) -> dict:
        return {
            "method": "OWASP Risk Rating Methodology", "severity": self.severity,
            "likelihood": round(self.likelihood, 2), "likelihood_level": self.likelihood_level,
            "impact": round(self.impact, 2), "impact_level": self.impact_level, "impact_basis": self.impact_basis,
            "factors": self.factors, "why": self.why,
        }  # fmt: skip

    def short(self) -> str:
        return f"{self.severity} (L {self.likelihood:.1f} {self.likelihood_level} x I {self.impact:.1f} {self.impact_level}, {self.impact_basis})"


def rate(kind: str, severity: Severity, stride: list[str], intel: dict, rule: str, files: list[str],
         exposure: str, data: str, factors: Factors | None = None) -> Rating:  # fmt: skip
    factors = factors or Factors()
    v, why = {}, {}
    skill, opportunity, size = AGENT_BY_EXPOSURE[exposure]
    for name, value, reason in (
        ("skill_level", skill, f"exposure {exposure}"),
        ("motive", MOTIVE_BY_DATA[data], f"data {data}"),
        ("opportunity", opportunity, f"exposure {exposure}"),
        ("size", size, f"exposure {exposure}"),
    ):
        v[name], why[name] = value, reason
    for name, value in factors.agent.items():
        v[name], why[name] = value, f"factors file {factors.path}"
    discovery, exploit, awareness = VULN_BY_KIND.get(kind, VULN_BY_KIND["code"])
    v["ease_of_discovery"], why["ease_of_discovery"] = discovery, f"kind of finding: {kind}"
    v["ease_of_exploit"], why["ease_of_exploit"] = exploit, f"kind of finding: {kind}"
    v["awareness"], why["awareness"] = awareness, f"kind of finding: {kind}"
    if (intel or {}).get("kev"):
        v["ease_of_exploit"], why["ease_of_exploit"] = 9, "CVE in CISA KEV: exploited in the wild"
        v["awareness"], why["awareness"] = 9, "CVE in CISA KEV: public knowledge"
    elif any(s.get("epss", 0) >= 0.1 for s in ((intel or {}).get("epss") or {}).values()):
        v["ease_of_exploit"], why["ease_of_exploit"] = max(exploit, 5), "EPSS 10% or more: exploitation is likely"
    v["intrusion_detection"] = factors.intrusion_detection
    why["intrusion_detection"] = f"factors file {factors.path}" if factors.path else "default: logged without review (OWASP 8)"
    mag = MAGNITUDE[severity]
    letters = {s[0] for s in stride}  # "Spoofing" -> "S"
    technical = {
        "loss_of_confidentiality": mag if "I" in letters or not letters else 1,
        "loss_of_integrity": mag if "T" in letters or not letters else 1,
        "loss_of_availability": mag if "D" in letters else 1,
        "loss_of_accountability": 7 if letters & {"S", "R"} else 1,
    }
    for name, value in technical.items():
        v[name] = value
        why[name] = f"STRIDE {''.join(sorted(letters)) or 'unknown'} x severity {severity.label}"
    for name, value in factors.business.items():
        v[name], why[name] = value, f"factors file {factors.path}"
    for o in factors.overrides:
        if o.matches(rule, files):
            for name, value in o.factors.items():
                v[name], why[name] = value, f"override in {factors.path}"
    likelihood = sum(v[k] for k in THREAT_AGENT + VULNERABILITY) / 8
    business_known = all(k in v for k in BUSINESS)
    impact_keys = BUSINESS if business_known else TECHNICAL
    impact = sum(v[k] for k in impact_keys) / 4
    return Rating(v, why, likelihood, impact, "business" if business_known else "technical")
