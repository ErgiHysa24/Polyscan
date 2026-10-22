from pathlib import Path

import pytest

from polyscan.models import Severity
from polyscan.tools import (
    parse_bandit,
    parse_checkov,
    parse_gitleaks,
    parse_osv,
    parse_semgrep,
    rel_path,
    scan_errors,
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


@pytest.mark.parametrize("parser", [parse_semgrep, parse_gitleaks, parse_osv, parse_bandit, parse_checkov])
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


@pytest.mark.parametrize("parser", [parse_semgrep, parse_osv, parse_bandit, parse_checkov])
def test_garbage_input_raises_value_error(parser):
    # The scanner turns this into a visible ERROR status, never a clean result.
    with pytest.raises(ValueError):
        parser("this is not json", "/ROOT")


def test_checkov_real_output_with_several_kinds_of_files():
    """Real output: a list with one object per kind (Kubernetes and Dockerfile)."""
    findings = parse_checkov(read("checkov.json"), "/ROOT")
    assert {f.language for f in findings} == {"kubernetes", "docker"}
    docker = next(f for f in findings if f.language == "docker")
    assert docker.rule.startswith("CKV_DOCKER_") and docker.file == "Dockerfile"  # no leading "/"
    assert docker.category == "config" and docker.line > 0
    assert all(f.severity == Severity.MEDIUM for f in findings)  # the free version gives none
    assert all(not f.file.startswith("/") for f in findings)


def test_checkov_single_kind_is_one_object_not_a_list():
    one = '{"check_type": "dockerfile", "results": {"failed_checks": [{"check_id": "CKV_DOCKER_2", ' \
          '"check_name": "HEALTHCHECK", "file_path": "/sub/Dockerfile", "file_line_range": [1, 6]}]}}'
    (f,) = parse_checkov(one, "/ROOT")
    assert f.file == "sub/Dockerfile" and f.line == 1 and f.language == "docker"


def test_checkov_empty_folder_prints_only_a_summary_and_means_no_findings():
    assert parse_checkov(read("checkov-empty.json"), "/ROOT") == []


def test_checkov_severity_is_used_when_the_platform_provides_it():
    out = '{"check_type": "dockerfile", "results": {"failed_checks": [{"check_id": "X", "check_name": "n", ' \
          '"file_path": "/Dockerfile", "file_line_range": [3, 3], "severity": "HIGH"}]}}'
    assert parse_checkov(out, "/ROOT")[0].severity == Severity.HIGH


def test_scan_errors_counts_checkov_parsing_errors_in_all_shapes():
    assert scan_errors(read("checkov-empty.json")) == 0
    one = {"check_type": "dockerfile", "summary": {"parsing_errors": 2}}
    import json

    assert scan_errors(json.dumps(one)) == 2
    assert scan_errors(json.dumps([one, one])) == 4
    assert scan_errors(read("checkov.json")) == 0
    assert scan_errors('{"errors": [1, 2, 3]}') == 3  # Semgrep / Bandit shape still works
