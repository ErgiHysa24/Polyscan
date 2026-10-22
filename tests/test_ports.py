"""polyscan ports: reading `ss` output and deciding what is exposed."""

import json

import pytest

from polyscan import cli
from polyscan.models import ERROR, OK, UNAVAILABLE, Severity
from polyscan.ports import Listener, check, findings_for, parse_ss
from polyscan.report import to_html, to_json, to_markdown, to_terminal

# Format of `ss -H -tulnp`. Replaced by real output once it exists (tests/fixtures/ss.txt, see below).
SAMPLE = """\
udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=654,fd=13))
tcp   LISTEN 0      4096    127.0.0.54:53            0.0.0.0:*
tcp   LISTEN 0      128     0.0.0.0:22               0.0.0.0:*    users:(("sshd",pid=801,fd=3))
tcp   LISTEN 0      128     [::]:22                  [::]:*       users:(("sshd",pid=801,fd=4))
tcp   LISTEN 0      511     *:80                     *:*          users:(("nginx",pid=900,fd=6))
tcp   LISTEN 0      4096    0.0.0.0:5432             0.0.0.0:*    users:(("docker-proxy",pid=1500,fd=4))
tcp   LISTEN 0      4096    [::]:5432                [::]:*       users:(("docker-proxy",pid=1507,fd=4))
tcp   LISTEN 0      511     127.0.0.1:6379           0.0.0.0:*    users:(("redis-server",pid=1600,fd=6))
tcp   LISTEN 0      4096    10.0.0.5:8080            0.0.0.0:*    users:(("my app",pid=1700,fd=3))
tcp   LISTEN 0      4096    [::1]:631                [::]:*
udp   UNCONN 0      0       0.0.0.0:11211            0.0.0.0:*
"""


# ----------------------------------------------------------------- parsing


def test_parse_all_address_forms():
    listeners, bad = parse_ss(SAMPLE)
    assert bad == 0 and len(listeners) == 11
    by = {(x.proto, x.host, x.port): x for x in listeners}
    assert by[("udp", "127.0.0.53", 53)].scope == "loopback"      # the %lo interface suffix is removed
    assert by[("tcp", "0.0.0.0", 22)].scope == "all"
    assert by[("tcp", "::", 22)].scope == "all"                   # IPv6 wildcard in brackets
    assert by[("tcp", "*", 80)].scope == "all"
    assert by[("tcp", "10.0.0.5", 8080)].scope == "interface"
    assert by[("tcp", "::1", 631)].scope == "loopback"
    assert by[("tcp", "10.0.0.5", 8080)].process == "my app"      # a name with a space
    assert by[("tcp", "127.0.0.54", 53)].process == ""            # ss may not be allowed to say


@pytest.mark.parametrize("line", ["garbage", "tcp LISTEN 0 1", "icmp x 0 0 1.2.3.4:5 0.0.0.0:*", "tcp LISTEN 0 0 nohostport 0:* ", "tcp LISTEN 0 0 1.2.3.4:99999 0:*", "tcp LISTEN 0 0 1.2.3.4:abc 0:*"])
def test_lines_that_cannot_be_read_are_counted_not_guessed(line):
    assert parse_ss(line) == ([], 1)


def test_blank_lines_are_not_errors():
    assert parse_ss("\n\n") == ([], 0)


# ----------------------------------------------------------------- what is exposed


def test_exposed_database_loopback_redis_and_expected_ports():
    listeners, _ = parse_ss(SAMPLE)
    findings = findings_for(listeners)
    by_rule = {f.rule: f for f in findings}
    pg = by_rule["exposed-postgresql"]
    assert pg.severity == Severity.HIGH and pg.file == "tcp/5432" and pg.category == "runtime"
    assert "every interface" in pg.message and "docker-proxy" in pg.message and "127.0.0.1:PORT:PORT" in pg.message
    assert len([f for f in findings if f.rule == "exposed-postgresql"]) == 1  # IPv4 and IPv6 listeners: one finding
    assert "exposed-redis" not in by_rule                      # Redis is on 127.0.0.1: fine
    assert by_rule["exposed-memcached"].file == "udp/11211"
    assert not any(f.file in ("tcp/22", "tcp/80") for f in findings)  # expected ports are silent
    assert not any(f.file.endswith("/53") or f.file.endswith("/631") for f in findings)  # loopback is never flagged


def test_unexpected_listener_and_the_expect_list():
    listeners, _ = parse_ss(SAMPLE)
    (f,) = [x for x in findings_for(listeners) if x.rule == "unexpected-listener"]
    assert f.severity == Severity.LOW and f.file == "tcp/8080" and "10.0.0.5" in f.message and "--expect" in f.message
    assert not [x for x in findings_for(listeners, (22, 80, 443, 8080)) if x.rule == "unexpected-listener"]


def test_docker_api_without_tls_is_critical():
    (f,) = findings_for([Listener("tcp", "0.0.0.0", 2375, "dockerd")])
    assert f.severity == Severity.CRITICAL and "Docker" in f.message


def test_a_service_only_on_loopback_gives_nothing():
    assert findings_for([Listener("tcp", "127.0.0.1", 5432, "postgres"), Listener("tcp", "::1", 3306, "")]) == []


# ----------------------------------------------------------------- the check


class P:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def run_check(proc, platform="linux", which=lambda n: "/usr/bin/ss"):
    return check(run=lambda *a, **k: proc, platform=platform, which=which)


def test_check_ok():
    r = run_check(P(SAMPLE))
    t = r.tools[0]
    assert t.status == OK and "11 listening sockets" in t.detail and r.kind == "host" and r.root == "this machine"
    assert any(f.rule == "exposed-postgresql" for f in r.findings)


def test_it_never_sends_anything_it_runs_ss_as_a_list():
    seen = {}

    def run(cmd, **kw):
        seen.update(cmd=cmd, kw=kw)
        return P(SAMPLE)

    check(run=run, platform="linux", which=lambda n: "/x")
    assert seen["cmd"] == ["ss", "-H", "-tulnp"] and "shell" not in seen["kw"]


def test_not_linux_or_no_ss_is_a_gap_not_a_clean_result():
    assert run_check(P(SAMPLE), platform="win32").tools[0].status == UNAVAILABLE
    assert run_check(P(SAMPLE), platform="darwin").tools[0].status == UNAVAILABLE
    r = run_check(P(SAMPLE), which=lambda n: None)
    assert r.tools[0].status == UNAVAILABLE and "iproute2" in r.tools[0].detail and r.had_gaps


@pytest.mark.parametrize("proc", [P("", "permission denied", 1), P("", "", 0), P("junk\nmore junk\n", "", 0)])
def test_failure_or_unreadable_output_is_an_error(proc):
    r = run_check(proc)
    assert r.tools[0].status == ERROR and r.had_errors and not r.findings


def test_oserror_is_an_error():
    def boom(*a, **k):
        raise OSError("nope")

    r = check(run=boom, platform="linux", which=lambda n: "/x")
    assert r.tools[0].status == ERROR


def test_a_few_unreadable_lines_do_not_hide_the_rest():
    r = run_check(P(SAMPLE + "weird line\n"))
    assert r.tools[0].status == OK and "1 lines not understood" in r.tools[0].detail


# ----------------------------------------------------------------- reports and the CLI


def test_reports_and_risk_can_read_the_result(tmp_path):
    r = run_check(P(SAMPLE))
    data = json.loads(to_json(r))
    assert data["kind"] == "host" and data["findings"]
    assert "Target: this machine" in to_terminal(r) and "host check" in to_html(r) and "ss" in to_markdown(r)
    from polyscan.risk import Context, assess, load_report, merge

    path = tmp_path / "ports.json"
    path.write_text(to_json(r), encoding="utf-8")
    risks = assess(merge([load_report(str(path))]), Context())
    pg = next(x for x in risks if x.rule == "exposed-postgresql")
    assert pg.level in ("high", "critical") and "firewall" in pg.mitigation.lower()


def test_cli_exit_codes(monkeypatch, capsys):
    from polyscan import ports

    monkeypatch.setattr(ports.subprocess, "run", lambda *a, **k: P(SAMPLE))
    monkeypatch.setattr(ports.shutil, "which", lambda n: "/x")
    monkeypatch.setattr(ports.sys, "platform", "linux")
    assert cli.main(["ports"]) == 1                                    # HIGH finding, default --fail-on high
    assert cli.main(["ports", "--fail-on", "critical"]) == 0
    assert cli.main(["ports", "--expect", "22,80,443,5432,11211,8080", "--fail-on", "low"]) == 0  # all expected
    assert cli.main(["ports", "--expect", "abc"]) == 2
    assert cli.main(["ports", "--expect", "70000"]) == 2
    capsys.readouterr()


def test_cli_ss_missing_is_exit_3_only_with_strict(monkeypatch, capsys):
    from polyscan import ports

    monkeypatch.setattr(ports.shutil, "which", lambda n: None)
    monkeypatch.setattr(ports.sys, "platform", "linux")
    assert cli.main(["ports"]) == 0
    assert cli.main(["ports", "--strict"]) == 3
    capsys.readouterr()
