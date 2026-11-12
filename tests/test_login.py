"""Form login for the live-site scan: the plan, the secret handling, and the proof that the login worked."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from polyscan import cli, logincheck
from polyscan.models import ERROR, ToolResult
from polyscan.scanner import build_command, dast
from polyscan.target import Target
from polyscan.tools import ScanOptions, Zap, check_login, zap_login_plan

OPTS = ScanOptions(target_url="http://host.docker.internal:5000", login_url="http://host.docker.internal:5000/login", login_user="alice",
                   login_password='p"w\\ }{%x%}\n'.replace("\n", ""), login_check_url="http://host.docker.internal:5000/account")  # fmt: skip


def test_plan_is_passive_and_valid_json_whatever_the_password():
    plan = json.loads(zap_login_plan(OPTS))
    types = [j["type"] for j in plan["jobs"]]
    assert types == ["spider", "passiveScan-wait", "report"] and not any("active" in t.lower() for t in types)
    ctx = plan["env"]["contexts"][0]
    assert ctx["users"][0]["credentials"] == {"username": "alice", "password": OPTS.login_password}  # quoting done by JSON
    assert ctx["authentication"]["parameters"]["loginRequestBody"] == "username={%username%}&password={%password%}"
    assert any("logout" in p for p in ctx["excludePaths"]) and ctx["urls"] == ["http://host.docker.internal:5000"]
    assert plan["jobs"][0]["parameters"]["user"] == "polyscan-user"


def test_password_is_never_on_the_command_line_or_in_repr(tmp_path):
    tool = Zap()
    cmd = build_command(tool, "docker", "http://localhost:5000", OPTS, tmp_path)
    assert OPTS.login_password not in " ".join(cmd) and "-i" in cmd and OPTS.login_password not in repr(OPTS)
    assert json.loads(tool.stdin_text(OPTS))["env"]["contexts"][0]["users"][0]["credentials"]["password"] == OPTS.login_password
    assert 'exit 3' in cmd[-1] and "zap.sh -cmd -autorun" in cmd[-1]  # a failed plan is not read as the baseline's "1 = findings"


@pytest.mark.parametrize("change, message", [
    ({"login_password": ""}, "empty"), ({"login_user": "a\nb"}, "control characters"), ({"login_user_field": "a b"}, "form field name"),
    ({"login_check_url": ""}, "login-check-url"), ({"login_password": "x" * 300}, "longer than"),
])  # fmt: skip
def test_bad_settings(change, message):
    from dataclasses import replace

    with pytest.raises(ValueError, match=message):
        check_login(replace(OPTS, **change))


# ---- a real little site, to test the proof of login for real
class Site(BaseHTTPRequestHandler):
    def _answer(self, code, headers=(), body=b"x"):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/account":
            ok = "session=good" in (self.headers.get("Cookie") or "")
            return self._answer(200) if ok else self._answer(302, [("Location", "/login")])
        self._answer(200)  # /login and /public

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if "username=alice" in body and "password=right+pw" in body:
            return self._answer(302, [("Set-Cookie", "session=good; Path=/"), ("Location", "/account")])
        self._answer(401)

    def log_message(self, *a):
        pass


@pytest.fixture()
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_login_proof_on_a_real_server(site):
    assert logincheck.verify(f"{site}/login", f"{site}/account", "alice", "right pw") == ""
    wrong = logincheck.verify(f"{site}/login", f"{site}/account", "alice", "wrong-secret")
    assert "did not work" in wrong and "302" in wrong and "wrong-secret" not in wrong
    # the redirect to the login page (which answers 200) must NOT count as success
    assert "answers 200 without logging in" in logincheck.verify(f"{site}/login", f"{site}/public", "alice", "right pw")
    assert "could not reach" in logincheck.verify("http://127.0.0.1:9/login", "http://127.0.0.1:9/a", "a", "b")
    assert "http or https" in logincheck.verify("file:///etc/passwd", f"{site}/account", "a", "b")


def test_failed_login_is_an_error_and_zap_does_not_run(site, monkeypatch):
    monkeypatch.setattr("polyscan.scanner.choose_how", lambda tool, mode: ("docker", ""))
    monkeypatch.setattr("polyscan.scanner.run_tool", lambda tool, *a, **k: pytest.fail("ZAP must not run") if tool.name == "zap" else ToolResult(tool.name, "ok"))
    port = int(site.rsplit(":", 1)[1])
    opts = ScanOptions(login_url=f"{site}/login", login_user="alice", login_password="wrong-secret", login_check_url=f"{site}/account")
    res = dast(Target(site, "127.0.0.1", port, True, ("127.0.0.1",)), opts=opts)
    zap = res.tools[0]
    assert zap.status == ERROR and "form login" in zap.detail and "wrong-secret" not in zap.detail
    assert not any("AUTHENTICATED" in n for n in res.notes)  # never claim an authenticated scan that did not happen


def test_cli_refuses_other_sites_and_missing_pieces(monkeypatch, capsys):
    monkeypatch.setenv("PW", "secret-pw")
    base = ["dast", "http://localhost:5000", "--login-user", "alice", "--login-password-env", "PW"]
    assert cli.main([*base, "--login-url", "http://evil.example/login", "--login-check-url", "http://localhost:5000/a"]) == 2
    assert "same site" in capsys.readouterr().err
    assert cli.main([*base, "--login-url", "http://localhost:5000/login"]) == 2  # no check URL
    assert cli.main([*base, "--login-url", "http://localhost:5000/login", "--login-check-url", "http://localhost:5000/a", "--auth-header-env", "PW"]) == 2
    monkeypatch.delenv("PW")
    assert cli.main([*base, "--login-url", "http://localhost:5000/login", "--login-check-url", "http://localhost:5000/a"]) == 2
    assert "secret-pw" not in capsys.readouterr().err
