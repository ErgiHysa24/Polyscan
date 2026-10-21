from pathlib import Path

import pytest

from polyscan.models import Severity
from polyscan.tools import (
    parse_bandit,
    parse_gitleaks,
    parse_osv,
    parse_semgrep,
    rel_path,
)

FIX = Path(__file__).parent / "fixtures"


def read(name):
    return (FIX / name).read_text(encoding="utf-8")


def test_rel_path_handles_local_docker_and_windows():
    assert rel_path("/ROOT/app/a.py", "/ROOT") == "app/a.py"
    assert rel_path("/src/app/a.py", "/some/other/root") == "app/a.py"
    assert rel_path("C:\\Users\\me\\proj\\app\\a.py", "C:\\Users\\me\\proj") == "app/a.py"
    assert rel_path("./a.py", "/ROOT") == "a.py"


def test_semgrep_real_output():
    findings = parse_semgrep(read("semgrep.json"), "/ROOT")
    assert len(findings) == 6
    by_lang = {f.language for f in findings}
    assert by_lang == {"python", "javascript", "java", "php", "rust"}
    js = next(f for f in findings if f.language == "javascript")
    assert js.severity == Severity.HIGH  # semgrep ERROR
    assert js.file == "javascript/app.js" and js.line > 0
    assert all(not f.file.startswith("/") for f in findings)


def test_gitleaks_real_output_hides_the_secret():
    findings = parse_gitleaks(read("gitleaks.json"), "/ROOT")
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "secret" and f.severity == Severity.HIGH
    assert f.file == "python/settings.py"
    assert "secret" in f.snippet and "q8Zt3" not in str(f.to_dict())


def test_gitleaks_clean_output_is_an_empty_list():
    assert parse_gitleaks("null", "/ROOT") == []
    assert parse_gitleaks("[]", "/ROOT") == []


@pytest.mark.parametrize("parser", [parse_semgrep, parse_gitleaks, parse_osv, parse_bandit])
def test_empty_output_is_an_error_not_a_clean_result(parser):
    with pytest.raises(ValueError):
        parser("", "/ROOT")
    with pytest.raises(ValueError):
        parser("   \n", "/ROOT")


def test_bandit_real_output_hides_hardcoded_passwords():
    findings = parse_bandit(read("bandit.json"), "/ROOT")
    assert len(findings) == 7
    secret = next(f for f in findings if f.rule.startswith("B105"))
    assert secret.category == "secret"
    assert "FAKE-PLACEHOLDER" not in str(secret.to_dict())
    shell = next(f for f in findings if f.rule.startswith("B602"))
    assert shell.severity == Severity.HIGH and shell.file == "python/app.py"


def test_osv_hand_written_schema_example():
    findings = parse_osv(read("osv.json"), "/ROOT")
    assert len(findings) == 4
    by_id = {f.rule: f for f in findings}
    # CVSS score from `groups` wins over the label from the database
    assert by_id["GHSA-p6mc-m468-83gw"].severity == Severity.HIGH  # 7.4
    assert by_id["GHSA-35jh-r3h4-6jhm"].severity == Severity.CRITICAL  # 9.8
    # no score: fall back to the label, MODERATE means medium
    assert by_id["GHSA-462w-v97r-4m45"].severity == Severity.MEDIUM
    # nothing at all: medium, the cautious default
    assert by_id["RUSTSEC-2020-0071"].severity == Severity.MEDIUM
    f = by_id["GHSA-p6mc-m468-83gw"]
    assert f.category == "dependency" and f.file == "javascript/package-lock.json"
    assert "lodash 4.17.15" in f.message


@pytest.mark.parametrize(
    "score,expected",
    [(0.0, Severity.INFO), (3.9, Severity.LOW), (4.0, Severity.MEDIUM), (7.0, Severity.HIGH), (9.0, Severity.CRITICAL)],
)
def test_cvss_bands(score, expected):
    assert Severity.from_cvss(score) == expected


@pytest.mark.parametrize("parser", [parse_semgrep, parse_osv, parse_bandit])
def test_garbage_input_raises_value_error(parser):
    # The scanner turns this into a visible ERROR status, never a clean result.
    with pytest.raises(ValueError):
        parser("this is not json", "/ROOT")
