"""Threat intelligence: CISA KEV and FIRST EPSS, on real saved answers. No network in these tests."""

import json
from pathlib import Path

import pytest

from polyscan import cli, intel, riskreport
from polyscan.models import Finding, Severity
from polyscan.risk import Context, assess

FIX = Path(__file__).parent / "fixtures"
KEV = json.loads((FIX / "kev.json").read_text())
EPSS = (FIX / "epss.json").read_text()


def dep(cve, severity=Severity.MEDIUM):
    return Finding("osv-scanner", severity, cve, f"lib 1.0: {cve} something", "pom.xml", 0, "dependency")


def fake_get(responses):
    def get(url):
        for prefix, body in responses.items():
            if url.startswith(prefix):
                if isinstance(body, Exception):
                    raise body
                return body.encode() if isinstance(body, str) else body
        raise OSError(f"unexpected url {url}")

    return get


def test_parse_real_kev():
    kev = intel.parse_kev(KEV)
    assert set(kev) == {"CVE-2019-11043", "CVE-2021-44228", "CVE-2017-5638"}
    assert kev["CVE-2021-44228"]["ransomware"] == "Known" and kev["CVE-2021-44228"]["dateAdded"]


def test_parse_real_epss_json_and_the_csv_format():
    scores = intel.parse_epss(EPSS)
    assert scores["CVE-2021-44228"]["epss"] == pytest.approx(0.99999) and scores["CVE-2026-69246"]["epss"] == pytest.approx(0.0037)
    csv_text = "#model_version:v2025.03.14,score_date:2026-11-10T12:55:00Z\ncve,epss,percentile\nCVE-2021-44228,0.99999,1.0\nnot-a-cve,0.5,0.5\n"
    from_csv = intel.parse_epss(csv_text)
    assert list(from_csv) == ["CVE-2021-44228"] and from_csv["CVE-2021-44228"]["date"] == "2026-11-10"


@pytest.mark.parametrize("bad", [{}, {"vulnerabilities": "x"}, {"vulnerabilities": [{"cveID": "nope"}]}])
def test_bad_kev_is_refused(bad):
    with pytest.raises(ValueError):
        intel.parse_kev(bad)


def test_out_of_range_epss_values_are_ignored():
    text = json.dumps({"data": [{"cve": "CVE-2020-0001", "epss": "7", "percentile": "0.5"}, {"cve": "CVE-2020-0002", "epss": "x", "percentile": "1"}]})
    assert intel.parse_epss(text) == {}


def make_intel():
    i = intel.Intel()
    i.kev = intel.parse_kev(KEV)
    i.epss = intel.parse_epss(EPSS)
    return i


def test_kev_sets_likelihood_to_5():
    (r,) = assess([dep("CVE-2021-44228")], Context("local", "internal"), intel=make_intel())
    assert r.likelihood == 5 and any("CISA KEV" in x and "ransomware" in x for x in r.reasons)
    assert "CVE-2021-44228" in r.intel["kev"]


def test_high_epss_adds_one_low_epss_changes_nothing():
    i = make_intel()
    i.kev = {}
    (high,) = assess([dep("CVE-2017-5638")], Context(), intel=i)
    (base,) = assess([dep("CVE-2017-5638")], Context())
    assert high.likelihood == min(5, base.likelihood + 1) and any("EPSS" in x for x in high.reasons)
    (low,) = assess([dep("CVE-2026-69246")], Context(), intel=i)
    assert low.likelihood == base.likelihood and any("below 10%" in x for x in low.reasons)


def test_unknown_cve_and_no_intel_change_nothing():
    (r,) = assess([dep("CVE-2020-9999")], Context(), intel=make_intel())
    (plain,) = assess([dep("CVE-2020-9999")], Context())
    assert r.likelihood == plain.likelihood and r.intel == {"kev": {}, "epss": {}}


def test_download_uses_the_mirror_when_cisa_fails_and_batches_epss():
    get = fake_get({intel.KEV_URLS[0]: OSError("blocked"), intel.KEV_URLS[1]: json.dumps(KEV), intel.EPSS_API: EPSS})
    i = intel.gather(["CVE-2021-44228", "CVE-2017-5638"], True, get=get)
    assert not i.problems and "github" in i.sources[0] and len(i.kev) == 3 and len(i.epss) == 3


def test_failed_sources_are_gaps_not_silence():
    get = fake_get({intel.KEV_URLS[0]: OSError("down"), intel.KEV_URLS[1]: OSError("down"), intel.EPSS_API: '{"status": "error"}'})
    i = intel.gather(["CVE-2021-44228"], True, get=get)
    assert len(i.problems) == 2 and "KEV" in i.problems[0] and "EPSS" in i.problems[1]
    text = riskreport.to_json(Context(), [], [], None, i)
    assert any("threat intelligence" in g for g in json.loads(text)["coverage_gaps"])


def test_epss_requests_are_batched_and_encoded():
    seen = []

    def get(url):
        seen.append(url)
        return b'{"status": "OK", "data": []}'

    cves = [f"CVE-2020-{n:04d}" for n in range(120)] + ["CVE-bad; rm -rf"]
    intel.epss_download(cves, get)
    assert len(seen) == 3 and all(u.startswith(intel.EPSS_API + "?cve=CVE-2020-") for u in seen)
    assert not any("rm" in u for u in seen)  # only well-formed CVE ids are ever sent


def test_reports_show_kev(tmp_path):
    risks = assess([dep("CVE-2021-44228")], Context(), intel=make_intel())
    i = make_intel()
    i.sources = ["test"]
    assert "KEV" in riskreport.to_terminal(Context(), risks, [], intel=i)
    assert "KEV" in riskreport.to_markdown(Context(), risks, [], None, i)
    assert "class=kev" in riskreport.to_html(Context(), risks, [], None, i)
    data = json.loads(riskreport.to_json(Context(), risks, [], None, i))
    assert data["risks"][0]["exploitation"]["kev"]["CVE-2021-44228"] and data["threat_intel"]["kev_entries"] == 3


def test_cli_offline_files(tmp_path, capsys):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"polyscan": "x", "root": ".", "findings": [dep("CVE-2021-44228").to_dict()]}))
    out = tmp_path / "risk.json"
    code = cli.main(["risk", str(report), "--kev-file", str(FIX / "kev.json"), "--epss-file", str(FIX / "epss.json"), "--json", str(out)])
    assert code == 0
    data = json.loads(out.read_text())
    assert data["risks"][0]["likelihood"] == 5 and len(data["threat_intel"]["sources"]) == 2


def test_cli_missing_intel_file_is_exit_3(tmp_path, capsys):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"polyscan": "x", "root": ".", "findings": [dep("CVE-2021-44228").to_dict()]}))
    assert cli.main(["risk", str(report), "--kev-file", str(tmp_path / "missing.json")]) == 3
