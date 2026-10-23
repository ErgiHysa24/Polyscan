"""Links a finding to the threat it makes possible: CVE / CWE  ->  OWASP Top 10  ->  STRIDE  ->  MITRE ATT&CK.

What is official and what is not
  * CVE and CWE identifiers come from the tools' own output (an advisory id, a `cweid` field) and are
    reported as they are.
  * The links from a CWE to an OWASP Top 10 (2021) category, a STRIDE threat and ATT&CK techniques are
    **polyscan's own judgement**, written by hand in the table below. MITRE does not publish one official
    CWE -> ATT&CK list, and a weakness can serve several techniques; the table keeps to the usual, obvious
    ones and leaves a CWE without technique when none fits (for example CSRF). Read it as a starting point
    for a threat model, not as a verdict. Technique names and IDs are those of ATT&CK Enterprise.
  * Nothing is fetched from the internet: the table is part of the program, so the same report always
    gives the same answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding

STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}

OWASP = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

# ATT&CK Enterprise techniques used below: id -> (name, tactic)
TECHNIQUES = {
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access / Persistence"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence / Privilege Escalation"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1611": ("Escape to Host", "Privilege Escalation"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1552.005": ("Unsecured Credentials: Cloud Instance Metadata API", "Credential Access"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.002": ("Brute Force: Password Cracking", "Credential Access"),
    "T1040": ("Network Sniffing", "Credential Access / Discovery"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access / Collection"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1005": ("Data from Local System", "Collection"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
}

# CWE -> (short name, OWASP key, STRIDE letters, ATT&CK technique ids)
CWE = {
    "79": ("Cross-site scripting", "A03", "STI", ["T1189", "T1539"]),
    "89": ("SQL injection", "A03", "TIE", ["T1190"]),
    "78": ("OS command injection", "A03", "TE", ["T1190", "T1059"]),
    "77": ("Command injection", "A03", "TE", ["T1190", "T1059"]),
    "94": ("Code injection", "A03", "TE", ["T1190", "T1059"]),
    "95": ("Eval injection", "A03", "TE", ["T1190", "T1059"]),
    "98": ("Remote file inclusion (PHP)", "A03", "TE", ["T1190", "T1059"]),
    "22": ("Path traversal", "A01", "IT", ["T1190", "T1083", "T1005"]),
    "502": ("Unsafe deserialization", "A08", "TE", ["T1190", "T1059"]),
    "611": ("XML external entity (XXE)", "A05", "ID", ["T1190", "T1005"]),
    "918": ("Server-side request forgery", "A10", "IE", ["T1190", "T1552.005"]),
    "352": ("Cross-site request forgery", "A01", "ST", []),
    "798": ("Hard-coded credentials", "A07", "SI", ["T1552.001", "T1078"]),
    "259": ("Hard-coded password", "A07", "SI", ["T1552.001", "T1078"]),
    "321": ("Hard-coded cryptographic key", "A02", "I", ["T1552.001"]),
    "327": ("Broken or risky cryptographic algorithm", "A02", "I", ["T1040"]),
    "328": ("Weak password hash", "A02", "I", ["T1110.002"]),
    "330": ("Insufficiently random values", "A02", "S", []),
    "295": ("Improper certificate validation", "A02", "SI", ["T1557"]),
    "319": ("Cleartext transmission of sensitive data", "A02", "I", ["T1040", "T1557"]),
    "200": ("Exposure of sensitive information", "A01", "I", ["T1592"]),
    "209": ("Error message with sensitive information", "A04", "I", ["T1592"]),
    "16": ("Configuration", "A05", "IE", []),
    "614": ("Cookie without the Secure flag", "A05", "I", ["T1539"]),
    "1004": ("Cookie without the HttpOnly flag", "A05", "I", ["T1539"]),
    "693": ("Protection mechanism failure (missing security header)", "A05", "T", ["T1189"]),
    "1021": ("Clickjacking", "A05", "T", []),
    "434": ("Unrestricted file upload", "A04", "TE", ["T1505.003", "T1190"]),
    "601": ("Open redirect", "A01", "S", ["T1189"]),
    "284": ("Improper access control", "A01", "IE", ["T1078"]),
    "285": ("Improper authorization", "A01", "IE", ["T1078"]),
    "862": ("Missing authorization", "A01", "IE", ["T1078"]),
    "863": ("Incorrect authorization", "A01", "IE", ["T1078"]),
    "287": ("Improper authentication", "A07", "S", ["T1078"]),
    "306": ("Missing authentication for a critical function", "A07", "SE", ["T1078"]),
    "307": ("No limit on failed login attempts", "A07", "S", ["T1110"]),
    "400": ("Uncontrolled resource consumption", "A04", "D", ["T1499"]),
    "250": ("Execution with unnecessary privileges", "A04", "E", ["T1611", "T1068"]),
    "269": ("Improper privilege management", "A04", "E", ["T1068"]),
    "1104": ("Use of unmaintained third-party components", "A06", "TIED", ["T1190"]),
}

CWE_ID = re.compile(r"CWE[-_ ]?(\d{1,5})", re.I)
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
ADVISORY_ID = re.compile(r"\b(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|RUSTSEC-\d{4}-\d{4}|PKSA-[\w-]+)\b", re.I)


def cwe_ids(value) -> list[str]:
    """'CWE-89', 'CWE_89: SQL injection', ['CWE-79', ...], 502 or '352' -> ['89'] ... (numbers only, in order)."""
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    out = []
    for item in items:
        text = str(item).strip()
        found = CWE_ID.findall(text) or (re.findall(r"^\d{1,5}$", text))
        for n in found:
            n = str(int(n))
            if n not in ("0",) and n not in out:
                out.append(n)
    return out


def cwe_field(value) -> str:
    """The text stored in Finding.cwe: 'CWE-89,CWE-79' (empty when there is none)."""
    return ",".join(f"CWE-{n}" for n in cwe_ids(value))


def cve_ids(f: Finding) -> list[str]:
    """CVE ids written in the finding's rule or message (OSV and Trivy findings carry them)."""
    return sorted({m.upper() for m in CVE_ID.findall(f"{f.rule} {f.message}")})


def advisory_ids(f: Finding) -> list[str]:
    return sorted({m.upper() for m in ADVISORY_ID.findall(f"{f.rule} {f.message}")})


@dataclass
class Threat:
    cwe: list[str]  # ["CWE-89"]
    cve: list[str]
    advisories: list[str]
    owasp: list[str]  # full names
    stride: list[str]  # full names
    attack: list[dict]  # {"id", "name", "tactic"}
    basis: str  # "cwe" (reported by the tool), "kind" (polyscan's guess from the kind of finding) or "none"

    def to_dict(self) -> dict:
        return {
            "basis": self.basis, "cwe": self.cwe, "cve": self.cve, "advisories": self.advisories,
            "owasp_top10": self.owasp, "stride": self.stride, "attack": self.attack,
        }  # fmt: skip


# When the tool reports no CWE, the KIND of finding (and a few well-known rule texts) still says what is at stake.
FALLBACKS = [
    (r"is listening on|unexpected listener|exposed-", ("A05", "IE", ["T1133", "T1046", "T1021"])),
    (r"privileged|docker\.sock|cap_add|network_mode|run as root|root user|\buser\b instruction", ("A05", "E", ["T1611", "T1068"])),
]
KIND_FALLBACK = {
    "secret": ("A07", "SI", ["T1552.001", "T1078"]),
    "dependency": ("A06", "TIED", ["T1190"]),
}


def threat_for(findings: list[Finding], kind: str = "") -> Threat:
    """The threat links of a group of findings (all of one kind of problem)."""
    cwes: list[str] = []
    cves: set[str] = set()
    adv: set[str] = set()
    for f in findings:
        for n in cwe_ids(getattr(f, "cwe", "")):
            if n not in cwes:
                cwes.append(n)
        cves.update(cve_ids(f))
        adv.update(advisory_ids(f))
    owasp: list[str] = []
    stride: set[str] = set()
    techniques: list[str] = []
    basis = "none"

    def add(o: str, s: str, ts: list[str]):
        if o and OWASP[o] not in owasp:
            owasp.append(OWASP[o])
        stride.update(s)
        for t in ts:
            if t not in techniques:
                techniques.append(t)

    known = [n for n in cwes if n in CWE]
    for n in known:
        _name, o, s, ts = CWE[n]
        add(o, s, ts)
        basis = "cwe"
    if not known:
        text = " ".join(f"{f.rule} {f.message}" for f in findings).lower()
        guess = KIND_FALLBACK.get(kind or (findings[0].category if findings else ""))
        for pattern, rule_guess in FALLBACKS:
            if re.search(pattern, text):
                guess = rule_guess
                break
        if guess:
            add(*guess)
            basis = "kind"
    return Threat(
        cwe=[f"CWE-{n}" for n in cwes], cve=sorted(cves), advisories=sorted(adv), owasp=owasp,
        stride=[STRIDE[c] for c in "STRIDE" if c in stride],
        attack=[{"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1]} for t in techniques],
        basis=basis,
    )  # fmt: skip
