"""CVE / CWE -> OWASP -> STRIDE -> MITRE ATT&CK links: the table is consistent, the ids come from real tool output."""

import json
import re
from pathlib import Path

import pytest

from polyscan import riskreport
from polyscan.models import Finding, Severity
from polyscan.risk import Context, assess, load_report
from polyscan.threats import (
    CWE, OWASP, STRIDE, TECHNIQUES, advisory_ids, cve_ids, cwe_field, cwe_ids, threat_for,
)  # fmt: skip
from polyscan.tools import parse_bandit, parse_progpilot, parse_semgrep, parse_spotbugs, parse_zap

FIX = Path(__file__).parent / "fixtures"


def fnd(**kw):
    base = dict(tool="t", severity=Severity.HIGH, rule="r", message="m", file="a", line=1, category="code")
    return Finding(**{**base, **kw})


# ------------------------------------------------------------------ the table itself
def test_the_table_only_uses_known_names():
    for cwe, (name, owasp, stride, techniques) in CWE.items():
        assert cwe.isdigit() and name
        assert owasp in OWASP, cwe
        assert stride and set(stride) <= set(STRIDE), cwe
        assert len(set(techniques)) == len(techniques), cwe
        for t in techniques:
            assert t in TECHNIQUES, f"CWE-{cwe}: {t}"


def test_technique_ids_have_the_attack_format_and_every_one_is_used():
    for tid, (name, tactic) in TECHNIQUES.items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), tid
        assert name and tactic
    used = {t for _n, _o, _s, ts in CWE.values() for t in ts}
    from polyscan.threats import FALLBACKS, KIND_FALLBACK

    used |= {t for _p, (_o, _s, ts) in FALLBACKS for t in ts} | {t for _o, _s, ts in KIND_FALLBACK.values() for t in ts}
    assert used == set(TECHNIQUES), f"unused: {set(TECHNIQUES) - used}; missing: {used - set(TECHNIQUES)}"


@pytest.mark.parametrize("tid, name", [("T1190", "Exploit Public-Facing Application"), ("T1552.001", "Unsecured Credentials: Credentials In Files"),
                                       ("T1059", "Command and Scripting Interpreter"), ("T1110.002", "Brute Force: Password Cracking")])  # fmt: skip
def test_well_known_technique_names(tid, name):
    assert TECHNIQUES[tid][0] == name


# ------------------------------------------------------------------ reading ids
@pytest.mark.parametrize("value, expected", [
    ("CWE-89", ["89"]), ("CWE_79", ["79"]), ("CWE-89: Improper Neutralization", ["89"]), (["CWE-79", "CWE-89: x"], ["79", "89"]),
    (502, ["502"]), ("352", ["352"]), ("-1", []), ("0", []), (None, []), ("", []), ("CWE-89,CWE-89", ["89"]), ("<script>", []),
])  # fmt: skip
def test_cwe_ids(value, expected):
    assert cwe_ids(value) == expected


def test_cwe_field_text():
    assert cwe_field(["CWE-79", "CWE-89"]) == "CWE-79,CWE-89" and cwe_field(None) == ""


def test_cve_and_advisory_ids_are_found_in_text():
    f = fnd(rule="CVE-2026-69246", message="guzzle: x. See GHSA-v5mv-p594-2x33 and cve-2026-1111 RUSTSEC-2020-0071")
    assert cve_ids(f) == ["CVE-2026-1111", "CVE-2026-69246"]
    assert advisory_ids(f) == ["GHSA-V5MV-P594-2X33", "RUSTSEC-2020-0071"]


# ------------------------------------------------------------------ CWE comes from the real tool output
def test_bandit_real_output_has_a_cwe():
    found = parse_bandit((FIX / "bandit.json").read_text(), "/p")
    pickle = [f for f in found if f.cwe == "CWE-502"]
    assert pickle
    t = threat_for(pickle)
    assert t.basis == "cwe" and t.cwe == ["CWE-502"] and "A08:2021 Software and Data Integrity Failures" in t.owasp
    assert [a["id"] for a in t.attack] == ["T1190", "T1059"] and t.stride == ["Tampering", "Elevation of privilege"]


def test_zap_real_output_has_a_cwe():
    found = parse_zap((FIX / "zap.json").read_text(), "http://localhost:8000")
    csrf = [f for f in found if f.cwe == "CWE-352"]
    assert csrf
    t = threat_for(csrf)
    assert t.cwe == ["CWE-352"] and t.owasp == [OWASP["A01"]] and t.attack == []  # ATT&CK has no good match for CSRF
    assert all(f.cwe == "" or f.cwe.startswith("CWE-") for f in found)


def test_progpilot_and_spotbugs_output_have_a_cwe():
    pp = parse_progpilot(json.dumps({"kind": "progpilot", "results": json.loads((FIX / "progpilot.json").read_text()), "unparsed": []}), "/p")
    assert [f.cwe for f in pp] == ["CWE-89", "CWE-79", "CWE-95", "CWE-78"]
    sb = parse_spotbugs((FIX / "spotbugs.xml").read_text(), "/nonexistent")
    assert [f.cwe for f in sb] == ["CWE-78", "CWE-89", "CWE-89"]
    assert [a["id"] for a in threat_for([pp[0]]).attack] == ["T1190"]


def test_semgrep_cwe_metadata_shapes():
    # The saved Semgrep fixture was reduced and has no metadata, so these two shapes follow Semgrep's documented
    # output ("cwe" is a list of "CWE-n: title" strings, older rules use one string): not checked on real output.
    def result(cwe):
        return json.dumps({"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1},
                                        "extra": {"message": "m", "severity": "ERROR", "lines": "x", "metadata": {"cwe": cwe}}}]})  # fmt: skip

    assert parse_semgrep(result(["CWE-89: SQL Injection", "CWE-564: Hibernate"]), "/p")[0].cwe == "CWE-89,CWE-564"
    assert parse_semgrep(result("CWE-79: XSS"), "/p")[0].cwe == "CWE-79"
    assert parse_semgrep(json.dumps({"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1}, "extra": {}}]}), "/p")[0].cwe == ""


# ------------------------------------------------------------------ grouping and fallbacks
def test_secrets_dependencies_and_open_ports_fall_back_to_the_kind():
    secret = threat_for([fnd(category="secret", rule="aws-key")])
    assert secret.basis == "kind" and [a["id"] for a in secret.attack] == ["T1552.001", "T1078"]
    dep = threat_for([fnd(category="dependency", rule="CVE-2026-69246", message="guzzle")])
    assert dep.basis == "kind" and dep.cve == ["CVE-2026-69246"] and dep.owasp == [OWASP["A06"]]
    port = threat_for([fnd(category="runtime", tool="ss", rule="exposed-postgresql", message="PostgreSQL is listening on 0.0.0.0")])
    assert [a["id"] for a in port.attack] == ["T1133", "T1046", "T1021"]
    assert threat_for([fnd(category="config", rule="x", message="nothing known")]).basis == "none"


def test_a_cwe_not_in_the_table_is_kept_but_not_invented_about():
    t = threat_for([fnd(cwe="CWE-9999")])
    assert t.cwe == ["CWE-9999"] and t.basis == "none" and t.attack == [] and t.owasp == []


def test_a_group_joins_the_links_of_all_its_findings():
    t = threat_for([fnd(cwe="CWE-89"), fnd(cwe="CWE-79")])
    assert t.cwe == ["CWE-89", "CWE-79"] and {a["id"] for a in t.attack} == {"T1190", "T1189", "T1539"}
    assert t.stride == ["Spoofing", "Tampering", "Information disclosure", "Elevation of privilege"]


# ------------------------------------------------------------------ in the register and the reports
def make_risks():
    return assess([fnd(cwe="CWE-89", rule="sqli", message="SQL injection"), fnd(category="secret", rule="key", message="leaked key")], Context())


def test_risk_json_has_the_threat_links():
    data = json.loads(riskreport.to_json(Context(), make_risks(), []))
    by_rule = {r["rule"]: r["threat"] for r in data["risks"]}
    assert by_rule["sqli"]["basis"] == "cwe" and by_rule["sqli"]["attack"][0] == {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
    assert by_rule["key"]["basis"] == "kind"
    assert any("own judgement" in m for m in data["method"])


def test_all_formats_show_the_techniques():
    risks = make_risks()
    for text in (riskreport.to_terminal(Context(), risks, []), riskreport.to_markdown(Context(), risks, []), riskreport.to_html(Context(), risks, [])):
        text = text.replace("\\", "")  # Markdown output escapes "-" and "."
        assert "T1190" in text and "CWE-89" in text and "T1552.001" in text
    assert "(by kind)" in riskreport.to_terminal(Context(), risks, [])


def test_threat_text_from_a_report_file_is_escaped(tmp_path):
    report = {"polyscan": "x", "root": "r", "kind": "folder", "tools": [], "notes": [], "findings": [
        {"tool": "t", "severity": "high", "rule": "CVE-2026-0001<img src=x onerror=alert(1)>", "message": "<script>alert(1)</script> CWE-89",
         "file": "a", "line": 1, "category": "code", "language": "", "cwe": "<script>alert(2)</script> CWE-79"}]}  # fmt: skip
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report))
    src = load_report(str(p))
    risks = assess(src.findings, Context())
    html = riskreport.to_html(Context(), risks, [src])
    assert "<script>" not in html and "<img" not in html
    assert risks[0].threat.cwe == ["CWE-79"]  # only the number survives, never the text around it
    assert "\x1b" not in riskreport.to_terminal(Context(), risks, [src])


def test_old_reports_without_a_cwe_field_still_load(tmp_path):
    report = {"polyscan": "x", "root": "r", "findings": [{"tool": "t", "severity": "low", "rule": "r", "message": "m", "file": "a", "line": 1}]}
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report))
    assert load_report(str(p)).findings[0].cwe == ""


def test_findings_keep_their_cwe_through_the_scanner_pipeline():
    from polyscan.scanner import add_snippets, dedupe

    f = fnd(cwe="CWE-89")
    assert dedupe([f])[0].cwe == "CWE-89" and add_snippets([f], Path("."))[0].cwe == "CWE-89"
    assert f.to_dict()["cwe"] == "CWE-89"
