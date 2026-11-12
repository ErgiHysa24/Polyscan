"""OWASP Risk Rating Methodology: the table, the bands, derived factors, the factors file."""

import json

import pytest

from polyscan import cli, riskreport
from polyscan.models import Finding, Severity
from polyscan.owasprr import ALL, BUSINESS, SEVERITY_TABLE, Factors, band, load, parse, rate
from polyscan.risk import Context, assess


@pytest.mark.parametrize("value, level", [(0, "LOW"), (2.99, "LOW"), (3, "MEDIUM"), (5.99, "MEDIUM"), (6, "HIGH"), (9, "HIGH")])
def test_bands(value, level):
    assert band(value) == level


def test_overall_severity_table_is_the_owasp_one():
    assert SEVERITY_TABLE[("HIGH", "HIGH")] == "Critical" and SEVERITY_TABLE[("LOW", "LOW")] == "Note"
    assert SEVERITY_TABLE[("HIGH", "LOW")] == SEVERITY_TABLE[("LOW", "HIGH")] == SEVERITY_TABLE[("MEDIUM", "MEDIUM")] == "Medium"
    assert SEVERITY_TABLE[("MEDIUM", "LOW")] == SEVERITY_TABLE[("LOW", "MEDIUM")] == "Low"
    assert SEVERITY_TABLE[("HIGH", "MEDIUM")] == SEVERITY_TABLE[("MEDIUM", "HIGH")] == "High"
    assert len(SEVERITY_TABLE) == 9


def test_every_factor_has_a_value_and_a_reason():
    r = rate("dependency", Severity.HIGH, ["Tampering", "Information disclosure"], {}, "CVE-1", ["a"], "internet", "personal")
    for k in ALL[:12]:
        assert 0 <= r.factors[k] <= 9 and r.why[k], k
    assert r.impact_basis == "technical" and not any(k in r.factors for k in BUSINESS)
    assert r.likelihood == pytest.approx((6 + 9 + 7 + 9 + 9 + 3 + 9 + 8) / 8)
    assert r.factors["loss_of_confidentiality"] == 7 and r.factors["loss_of_availability"] == 1


def test_kev_and_epss_raise_ease_of_exploit():
    kev = rate("dependency", Severity.MEDIUM, [], {"kev": {"CVE-1": {}}}, "r", [], "internet", "personal")
    assert kev.factors["ease_of_exploit"] == 9 and "KEV" in kev.why["ease_of_exploit"]
    epss = rate("dependency", Severity.MEDIUM, [], {"kev": {}, "epss": {"CVE-1": {"epss": 0.5}}}, "r", [], "internet", "personal")
    assert epss.factors["ease_of_exploit"] == 5


def test_context_moves_the_threat_agent():
    a = rate("code", Severity.HIGH, [], {}, "r", [], "internet", "personal")
    b = rate("code", Severity.HIGH, [], {}, "r", [], "local", "public")
    assert a.likelihood > b.likelihood and b.factors["size"] == 2 and b.factors["motive"] == 1


def test_factors_file_business_impact_and_overrides():
    f = parse({"version": 1, "threat_agent": {"skill_level": 9}, "intrusion_detection": 1,
               "business_impact": {"financial_damage": 7, "reputation_damage": 9, "non_compliance": 7, "privacy_violation": 9},
               "overrides": [{"rule": "B6*", "factors": {"ease_of_exploit": 1}}]}, "f.json")  # fmt: skip
    r = rate("code", Severity.LOW, [], {}, "B608", ["a.py"], "internet", "personal", f)
    assert r.impact_basis == "business" and r.impact == 8 and r.impact_level == "HIGH"
    assert r.factors["skill_level"] == 9 and r.factors["intrusion_detection"] == 1 and r.factors["ease_of_exploit"] == 1
    assert "override" in r.why["ease_of_exploit"]


@pytest.mark.parametrize("data, message", [
    ({"version": 2}, "version"),
    ({"version": 1, "extra": 1}, "unknown field"),
    ({"version": 1, "threat_agent": {"skill": 3}}, "threat_agent takes"),
    ({"version": 1, "threat_agent": {"size": 10}}, "0 to 9"),
    ({"version": 1, "intrusion_detection": True}, "0 to 9"),
    ({"version": 1, "business_impact": {"financial_damage": 3}}, "all four"),
    ({"version": 1, "overrides": [{"factors": {"awareness": 1}}]}, "rule or a file"),
    ({"version": 1, "overrides": [{"rule": "x", "factors": {"luck": 1}}]}, "factors must be"),
])  # fmt: skip
def test_bad_factors_files(data, message):
    with pytest.raises(ValueError, match=message):
        parse(data)


def test_in_the_register_and_reports(tmp_path, capsys):
    f = Finding("bandit", Severity.HIGH, "B608", "SQL", "a.py", 1, "code", cwe="CWE-89")
    (r,) = assess([f], Context())
    assert r.owasp and r.owasp.severity in ("Note", "Low", "Medium", "High", "Critical")
    d = json.loads(riskreport.to_json(Context(), [r], []))["risks"][0]["owasp_risk_rating"]
    assert d["method"] == "OWASP Risk Rating Methodology" and len(d["factors"]) == 12
    assert "OWASP Risk Rating:" in riskreport.to_terminal(Context(), [r], [])
    assert "OWASP factors" in riskreport.to_html(Context(), [r], [])
    report = tmp_path / "s.json"
    report.write_text(json.dumps({"polyscan": "x", "root": ".", "findings": [f.to_dict()]}))
    bad = tmp_path / "f.json"
    bad.write_text('{"version": 1, "threat_agent": {"size": 99}}')
    assert cli.main(["risk", str(report), "--factors", str(bad)]) == 2
    with pytest.raises(ValueError):
        load(str(tmp_path / "missing.json"))
    assert isinstance(Factors().intrusion_detection, int)
