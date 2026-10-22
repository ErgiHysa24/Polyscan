"""Scanning a running site: the ZAP report, the command, the guards on the target."""

import json
import socket
import sys
from pathlib import Path

import pytest

from polyscan import cli
from polyscan.models import ERROR, OK, UNAVAILABLE, Severity
from polyscan.report import to_html, to_json, to_markdown, to_terminal
from polyscan.scanner import build_command, dast, run_tool
from polyscan.target import classify
from polyscan.tools import ScanOptions, Zap, parse_zap

FIX = Path(__file__).parent / "fixtures"
ZAP_REPORT = (FIX / "zap.json").read_text(encoding="utf-8")
DOCKER_OPTS = ScanOptions(target_url="http://host.docker.internal:8000", zap_minutes=2)


@pytest.fixture
def dns(monkeypatch):
    table = {"localhost": ["127.0.0.1"], "shop.example.com": ["93.184.216.34"]}

    def fake(host, port, type=0, **kwargs):
        if host in table:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
        try:
            socket.inet_pton(socket.AF_INET, host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (host, port, 0, 0))]
        except OSError:
            raise socket.gaierror(-2, "Name or service not known") from None

    monkeypatch.setattr(socket, "getaddrinfo", fake)


# ----------------------------------------------------------------- parser


def test_zap_real_output():
    findings = parse_zap(ZAP_REPORT, "http://localhost:8000")
    assert len(findings) == 5
    by_rule = {f.rule: f for f in findings}
    assert by_rule["10038-1"].severity == Severity.MEDIUM  # riskcode 2
    assert by_rule["10010"].severity == Severity.LOW  # riskcode 1
    assert by_rule["10038-1"].message == "Content Security Policy (CSP) Header Not Set (4 URLs)"
    assert by_rule["10202"].message == "Absence of Anti-CSRF Tokens"  # one URL: no count
    assert all(f.category == "runtime" and f.line == 0 and f.tool == "zap" for f in findings)


def test_the_address_the_person_typed_is_shown_not_the_one_the_container_saw():
    findings = parse_zap(ZAP_REPORT, "http://localhost:8000")
    assert all(f.file.startswith("http://localhost:8000") for f in findings)
    assert not any("host.docker.internal" in f.file for f in findings)
    ipv6 = parse_zap(ZAP_REPORT, "http://[::1]:8000")
    assert all(f.file.startswith("http://[::1]:8000") for f in ipv6)


def test_risk_codes_map_to_severities():
    def report(code):
        return json.dumps({"@programName": "ZAP", "site": [{"@name": "http://x", "alerts": [
            {"pluginid": "1", "alertRef": "1", "name": "n", "riskcode": code, "count": "1",
             "instances": [{"uri": "http://x/a"}]}]}]})  # fmt: skip

    assert [parse_zap(report(c), "http://x")[0].severity for c in "0123"] == [
        Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
    ]  # fmt: skip


def test_a_report_with_no_alerts_is_no_findings():
    assert parse_zap('{"@programName": "ZAP", "site": [{"@name": "http://x", "alerts": []}]}', "http://x") == []
    assert parse_zap('{"@programName": "ZAP", "site": []}', "http://x") == []


@pytest.mark.parametrize("text", ["", "   ", "not json", "[]", '{"site": []}', '{"@programName": "Other"}'])
def test_anything_that_is_not_a_zap_report_is_an_error_not_a_clean_result(text):
    with pytest.raises(ValueError):
        parse_zap(text, "http://x")


def test_page_addresses_from_the_site_cannot_break_the_html_report():
    evil = json.dumps({"@programName": "ZAP", "site": [{"@name": "http://x", "alerts": [
        {"pluginid": "1", "name": "<script>alert(1)</script>", "riskcode": "2", "count": "1",
         "instances": [{"uri": "http://x/<img src=x onerror=alert(2)>"}]}]}]})  # fmt: skip
    result = dast_result(parse_zap(evil, "http://x"))
    page = to_html(result)
    assert "<script>alert(1)" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page


# ---------------------------------------------------------------- command


def test_the_zap_command_runs_the_pinned_image_without_mounting_the_project(tmp_path):
    work = tmp_path / "w"
    cmd = build_command(Zap(), "docker", "http://localhost:8000", DOCKER_OPTS, work, "polyscan-zap-1234")
    assert cmd[:3] == ["docker", "run", "--rm"] and cmd[cmd.index("--name") + 1] == "polyscan-zap-1234"
    assert "host.docker.internal:host-gateway" in cmd
    assert f"{work}:/zap/wrk:rw" in cmd  # the only writable mount
    assert not any(a.endswith(":/src:ro") for a in cmd)  # no project folder at all
    assert cmd[cmd.index("-w") + 1] == "/zap/wrk"
    image = cmd[cmd.index("-w") + 2]
    assert "@sha256:" in image
    tail = cmd[cmd.index(image) + 1:]
    assert tail == ["zap-baseline.py", "-t", "http://host.docker.internal:8000", "-J", "zap-report.json", "-m", "2"]
    assert "-a" not in tail and "zap-full-scan.py" not in cmd  # passive only


def test_zap_has_no_local_mode():
    assert Zap().local_ok is False
    res = dast(classify_local(), "local")
    (tool,) = res.tools
    assert tool.status == UNAVAILABLE and "only in Docker" in tool.detail


def classify_local():
    from polyscan.target import Target

    return Target("http://localhost:8000", "localhost", 8000, True, ("127.0.0.1",))


def dast_result(findings):
    from polyscan.models import ToolResult
    from polyscan.scanner import ScanResult

    return ScanResult("http://x", {}, [ToolResult("zap", OK, "via docker", list(findings))], kind="site")


# ----------------------------------------------- running (docker replaced)


def fake_docker(monkeypatch, code, write=None):
    """Replace the `docker run` command with a Python one that writes into the report folder."""

    def fake_build(tool, how, root, opts, workdir=None, name=None):
        script = f"import pathlib, sys\nw = pathlib.Path({str(workdir)!r})\n"
        if write is not None:
            script += f"(w / 'zap-report.json').write_text({write!r})\n"
        script += f"sys.stderr.write('zap said something'); sys.exit({code})"
        return [sys.executable, "-c", script]

    monkeypatch.setattr("polyscan.scanner.build_command", fake_build)


def test_report_file_is_read_and_parsed(monkeypatch):
    fake_docker(monkeypatch, 2, write=ZAP_REPORT)  # exit 2 = warnings, which is normal
    res = run_tool(Zap(), "docker", "http://localhost:8000", DOCKER_OPTS, 30)
    assert res.status == OK and len(res.findings) == 5


@pytest.mark.parametrize("code", [0, 1, 2])
def test_exit_codes_0_1_2_all_mean_it_ran(monkeypatch, code):
    fake_docker(monkeypatch, code, write='{"@programName": "ZAP", "site": []}')
    assert run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 30).status == OK


def test_exit_3_with_no_report_is_a_failure_not_a_clean_site(monkeypatch):
    """Real ZAP exits 3 and writes nothing when the site does not answer."""
    fake_docker(monkeypatch, 3, write=None)
    res = run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 30)
    assert res.status == ERROR and "exit code 3" in res.detail and res.findings == []


def test_a_missing_report_after_exit_0_is_a_failure(monkeypatch):
    fake_docker(monkeypatch, 0, write=None)
    res = run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 30)
    assert res.status == ERROR and "no report file" in res.detail


def test_an_empty_or_foreign_report_is_a_failure(monkeypatch):
    fake_docker(monkeypatch, 0, write="   ")
    assert run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 30).status == ERROR
    fake_docker(monkeypatch, 0, write='{"hello": 1}')
    res = run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 30)
    assert res.status == ERROR and "not a ZAP report" in res.detail


def test_the_report_folder_is_removed_afterwards(monkeypatch, tmp_path):
    seen = []

    def fake_build(tool, how, root, opts, workdir=None, name=None):
        seen.append(workdir)
        return [sys.executable, "-c", "pass"]

    monkeypatch.setattr("polyscan.scanner.build_command", fake_build)
    run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 30)
    assert seen and seen[0] is not None and not seen[0].exists()


def test_a_timeout_stops_the_container(monkeypatch):
    stopped = []
    monkeypatch.setattr("polyscan.scanner._stop_container", stopped.append)
    monkeypatch.setattr(
        "polyscan.scanner.build_command",
        lambda *a, **k: [sys.executable, "-c", "import time; time.sleep(30)"],
    )
    res = run_tool(Zap(), "docker", "http://x", DOCKER_OPTS, 1)
    assert res.status == ERROR and "timed out" in res.detail
    assert len(stopped) == 1 and stopped[0].startswith("polyscan-zap-")


# --------------------------------------------------------- the guard (CLI)


class Called(Exception):
    pass


def run_cli(monkeypatch, *args, result=None):
    calls = []

    def fake_dast(target, mode, opts, timeout):
        calls.append((target, mode, opts))
        if result is not None:
            return result
        return dast(target, mode, opts, timeout, tools=[])  # no tool: nothing is sent anywhere

    monkeypatch.setattr(cli, "dast", fake_dast)
    return cli.main(["dast", *args]), calls


@pytest.mark.parametrize("url", ["http://localhost:5000", "http://127.0.0.1:8000", "http://192.168.1.20", "http://[::1]:3000"])
def test_own_machine_and_private_network_need_no_extra_option(monkeypatch, dns, url):
    code, calls = run_cli(monkeypatch, url)
    assert code == 0 and len(calls) == 1 and calls[0][0].local


@pytest.mark.parametrize("url", ["https://shop.example.com", "http://93.184.216.34/", "http://8.8.8.8"])
def test_other_sites_are_refused_without_the_explicit_option(monkeypatch, dns, capsys, url):
    code, calls = run_cli(monkeypatch, url)
    assert code == 2 and calls == []  # the scan function was never reached
    err = capsys.readouterr().err
    assert "--allow-remote" in err and "written" in err and "illegal" in err


def test_the_explicit_option_allows_it_and_the_report_says_so(monkeypatch, dns, capsys, tmp_path):
    out = tmp_path / "r.json"
    code, calls = run_cli(monkeypatch, "https://shop.example.com", "--allow-remote", "--json", str(out))
    assert code == 0 and len(calls) == 1 and calls[0][0].local is False
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["kind"] == "site" and any("REMOTE TARGET" in n for n in data["notes"])
    assert "NOTE: REMOTE TARGET" in capsys.readouterr().out


def test_the_option_changes_nothing_for_local_targets(monkeypatch, dns, tmp_path):
    out = tmp_path / "r.json"
    run_cli(monkeypatch, "http://localhost:5000", "--allow-remote", "--json", str(out))
    assert json.loads(out.read_text(encoding="utf-8"))["notes"] == []  # no false alarm


@pytest.mark.parametrize(
    "url",
    ["http://localhost@93.184.216.34/", "ftp://localhost/", "localhost:5000", "http://nope.invalid/", ""],
)
def test_bad_or_tricky_urls_are_refused_even_with_the_option(monkeypatch, dns, capsys, url):
    code, calls = run_cli(monkeypatch, url, "--allow-remote")
    assert code == 2 and calls == []
    assert capsys.readouterr().err.startswith("error:")


@pytest.mark.parametrize("minutes", ["0", "31", "-1"])
def test_minutes_are_limited(monkeypatch, dns, minutes):
    code, calls = run_cli(monkeypatch, "http://localhost:5000", "--minutes", minutes)
    assert code == 2 and calls == []


def test_there_is_no_option_for_active_attacks():
    assert "--active" not in cli.build_parser().format_help()
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["dast", "http://localhost", "--active"])


def test_exit_codes_follow_the_findings(monkeypatch, dns):
    from polyscan.models import Finding

    high = Finding("zap", Severity.HIGH, "1", "m", file="http://localhost:5000", category="runtime")
    medium = Finding("zap", Severity.MEDIUM, "2", "m", file="http://localhost:5000", category="runtime")
    assert run_cli(monkeypatch, "http://localhost:5000", result=dast_result([high]))[0] == 1
    assert run_cli(monkeypatch, "http://localhost:5000", result=dast_result([medium]))[0] == 0
    assert run_cli(monkeypatch, "http://localhost:5000", "--fail-on", "medium", result=dast_result([medium]))[0] == 1


# ------------------------------------------------------------ dast() itself


def test_dast_gives_the_tool_the_container_address_but_reports_the_original(monkeypatch, dns):
    seen = {}

    def fake_run(tool, how, root, opts, timeout):
        seen.update(root=root, url=opts.target_url, how=how)
        from polyscan.models import ToolResult

        return ToolResult(tool.name, OK, "via docker")

    monkeypatch.setattr("polyscan.scanner.run_tool", fake_run)
    monkeypatch.setattr("polyscan.scanner.choose_how", lambda tool, mode: ("docker", ""))
    res = dast(classify("http://localhost:5000/app"), "docker")
    assert seen == {"root": "http://localhost:5000/app", "url": "http://host.docker.internal:5000/app", "how": "docker"}
    assert res.root == "http://localhost:5000/app" and res.kind == "site" and res.notes == []


def test_remote_scan_note_is_in_every_report_format(dns):
    res = dast(classify("https://shop.example.com"), "local")  # unavailable: nothing is sent
    res.notes.append("REMOTE TARGET: <b>x</b>")
    assert "NOTE: REMOTE TARGET" in to_terminal(res)
    assert "REMOTE TARGET" in to_markdown(res)
    assert "&lt;b&gt;x&lt;/b&gt;" in to_html(res) and "<b>x</b>" not in to_html(res)
    assert json.loads(to_json(res))["notes"]
    assert "Target: https://shop.example.com" in to_terminal(res)


def test_an_empty_tool_list_means_no_tools_not_the_default_tools(dns):
    """Regression: `tools or default` treated [] as 'use the defaults' and started Docker."""
    from polyscan.scanner import scan

    assert dast(classify_local(), "auto", tools=[]).tools == []
    assert scan(Path("."), "auto", tools=[]).tools == []


# ----------------------------------------------------------------- authenticated scan

from polyscan.tools import AUTH_FILE, check_auth, zap_auth_properties  # noqa: E402

SECRET = "Bearer s3cr3t-T0KEN.abc"


def test_the_secret_is_in_the_settings_file_never_on_the_command_line(tmp_path):
    opts = ScanOptions(target_url="http://host.docker.internal:8000", auth_name="Authorization", auth_value=SECRET)
    tool = Zap()
    tool.prepare(tmp_path, opts)
    text = (tmp_path / AUTH_FILE).read_text(encoding="utf-8")
    assert "matchstr=Authorization" in text and f"replacement={SECRET}" in text
    cmd = build_command(tool, "docker", "http://localhost:8000", opts, tmp_path, "n")
    assert not any("s3cr3t" in part for part in cmd)
    assert "-configfile /zap/wrk/" + AUTH_FILE in cmd[cmd.index("-z") + 1]


def test_without_a_login_nothing_is_added(tmp_path):
    tool = Zap()
    tool.prepare(tmp_path, ScanOptions(target_url="http://x"))
    assert not (tmp_path / AUTH_FILE).exists()
    assert "-z" not in tool.docker_cmd(ScanOptions(target_url="http://x"))


def test_the_secret_does_not_show_in_repr():
    assert "s3cr3t" not in repr(ScanOptions(auth_name="Authorization", auth_value=SECRET))


@pytest.mark.parametrize("name,value", [
    ("Authorization", "Bearer a\nreplacer.full_list(1).enabled=true"),  # would add a second setting
    ("Authorization", "a,b"), ("Authorization", "a\\b"), ("Authorization", 'a"b'), ("Authorization", "#x"),
    ("Authorization", ""), ("Authorization", "x" * 5000),
    ("X-Evil\nA", "v"), ("", "v"), ("Bad Name", "v"),
])  # fmt: skip
def test_unsafe_header_is_refused_without_repeating_it(name, value):
    with pytest.raises(ValueError) as err:
        check_auth(name, value)
    assert value[:10] not in str(err.value) or value[:10].strip() == ""


@pytest.mark.parametrize("value", ["Bearer eyJhbGciOi.J9.sig-_x", "session=abc123; csrf=x/y+z=="])
def test_normal_tokens_and_cookies_are_accepted(value):
    assert "replacement=" + value in zap_auth_properties("Cookie", value)


def test_the_secret_is_removed_from_whatever_the_tool_prints(monkeypatch):
    import subprocess

    class P:
        returncode = 3
        stdout = f"debug {SECRET}"
        stderr = f"bad header {SECRET}"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    opts = ScanOptions(target_url="http://x", auth_name="Authorization", auth_value=SECRET)
    result = run_tool(Zap(), "docker", "http://localhost:8000", opts, 10)
    assert result.status == ERROR and "s3cr3t" not in result.detail and "[hidden]" in result.detail


def test_cli_refuses_when_the_variable_is_missing_or_bad(monkeypatch, capsys, dns):
    monkeypatch.delenv("MY_TOKEN", raising=False)
    assert cli.main(["dast", "http://localhost:8000", "--auth-header-env", "MY_TOKEN"]) == 2
    monkeypatch.setenv("MY_TOKEN", "bad,value")
    assert cli.main(["dast", "http://localhost:8000", "--auth-header-env", "MY_TOKEN"]) == 2
    assert "bad,value" not in capsys.readouterr().err


def test_cli_needs_https_for_a_remote_site_with_a_login(monkeypatch, capsys, dns):
    monkeypatch.setenv("MY_TOKEN", "Bearer abc")
    code = cli.main(["dast", "http://shop.example.com/", "--allow-remote", "--auth-header-env", "MY_TOKEN"])
    assert code == 2 and "https" in capsys.readouterr().err


def test_the_report_says_it_was_an_authenticated_scan(monkeypatch):
    from polyscan import scanner
    from polyscan.target import classify as c

    monkeypatch.setattr(scanner, "run_tool", lambda *a, **k: scanner.ToolResult("zap", OK, "via docker"))
    monkeypatch.setattr(scanner, "choose_how", lambda t, m: ("docker", ""))
    opts = ScanOptions(auth_name="Authorization", auth_value=SECRET)
    result = scanner.dast(c("http://127.0.0.1:8000"), "docker", opts)
    assert any("AUTHENTICATED" in n for n in result.notes)
    assert "s3cr3t" not in to_json(result) and "s3cr3t" not in to_html(result)
