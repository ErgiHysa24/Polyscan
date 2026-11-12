"""TLS check (testssl.sh): parser on real output, the command, and when it is skipped or fails."""

import json
from pathlib import Path

import pytest

from polyscan.models import SKIPPED, Severity
from polyscan.scanner import build_command, dast
from polyscan.target import Target
from polyscan.tools import ScanOptions, TestSsl, parse_testssl, site_tools

REAL = (Path(__file__).parent / "fixtures" / "testssl.json").read_text()
URL = "https://localhost:8443"


def test_real_output_local_site():
    found = {f.rule: f for f in parse_testssl(REAL, URL)}
    assert "tls-cert_trust" not in found and "tls-engine_problem" not in found  # artefact of the Docker host name; tool noise
    chain = found["tls-cert_chain_of_trust"]
    assert chain.severity == Severity.LOW and "local test certificate" in chain.message and "self signed" in chain.message
    assert found["tls-security_headers"].severity == Severity.MEDIUM and found["tls-HSTS"].severity == Severity.LOW
    assert found["tls-cipherlist_OBSOLETED"].cwe == "CWE-310"
    assert all(f.tool == "testssl" and f.category == "runtime" and f.file == URL for f in found.values())
    assert len(found) == 7


def test_real_site_keeps_the_certificate_severity():
    remote = REAL.replace("host.docker.internal/172.17.0.1", "example.org/93.184.216.34")
    found = {f.rule: f for f in parse_testssl(remote, "https://example.org")}
    assert found["tls-cert_chain_of_trust"].severity == Severity.CRITICAL and found["tls-cert_trust"].severity == Severity.HIGH


def test_fatal_means_the_scan_did_not_happen():
    dead = json.dumps([{"id": "scanProblem", "ip": "127.0.0.1/127.0.0.1", "port": "9", "severity": "FATAL", "finding": "Can't connect to '127.0.0.1:9'"},
                       {"id": "scanTime", "severity": "WARN", "finding": "Scan interrupted"}])  # fmt: skip
    with pytest.raises(ValueError, match="could not test the site"):
        parse_testssl(dead, URL)
    with pytest.raises(ValueError):
        parse_testssl("{}", URL)
    assert parse_testssl("[]", URL) == []  # a perfect configuration really has nothing at LOW or above


def test_command_configuration_checks_only(tmp_path):
    tool = TestSsl()
    cmd = build_command(tool, "docker", URL, ScanOptions(target_url="https://host.docker.internal:8443"), tmp_path)
    text = " ".join(cmd)
    assert "@sha256:" in tool.image and f"{tmp_path}:/out:rw" in text and cmd[-1] == "https://host.docker.internal:8443"
    assert "--jsonfile /out/testssl.json" in text
    for forbidden in ("--vulnerable", " -U", "--heartbleed", "--robot", "--full", "docker.sock"):
        assert forbidden not in text, forbidden


def test_http_targets_are_skipped_with_the_reason(monkeypatch):
    monkeypatch.setattr("polyscan.scanner.choose_how", lambda tool, mode: ("docker", ""))
    monkeypatch.setattr("polyscan.scanner.run_tool", lambda tool, *a, **k: pytest.fail("must not run") if tool.name == "testssl" else __import__("polyscan.models", fromlist=["ToolResult"]).ToolResult(tool.name, "ok"))
    res = dast(Target("http://localhost:8000", "localhost", 8000, True, ("127.0.0.1",)))
    tls = [t for t in res.tools if t.name == "testssl"][0]
    assert tls.status == SKIPPED and "no TLS to check" in tls.detail
    assert [t.name for t in site_tools()] == ["zap", "testssl"]
