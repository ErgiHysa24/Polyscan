"""Database configuration audit: each rule, what must NOT be flagged, and that passwords are never printed."""

import json
import subprocess
import sys

import pytest

from polyscan import dbaudit
from polyscan.models import OK, SKIPPED, Severity
from polyscan.scanner import run_tool
from polyscan.threats import threat_for
from polyscan.tools import DbConfig, ScanOptions, all_tools, parse_dbaudit


def rules(findings):
    return sorted({f["rule"].replace("polyscan-db-", "") for f in findings})


def test_compose_environment_both_styles():
    text = """
services:
  db:
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_HOST_AUTH_METHOD: trust
  my:
    environment:
      - MYSQL_ALLOW_EMPTY_PASSWORD=yes
      - MYSQL_ROOT_PASSWORD="S3cret-Long-Random-9f2c"
      - MARIADB_PASSWORD=${DB_PASS}
"""
    found = dbaudit.check_env_lines(text, "docker-compose.yml")
    assert rules(found) == ["mysql-empty-password", "postgres-trust", "weak-password"]
    assert [f["line"] for f in found if f["rule"].endswith("weak-password")] == [5]


def test_values_from_variables_and_strong_passwords_are_not_judged():
    text = "POSTGRES_PASSWORD=${PG_PASS}\nMYSQL_ROOT_PASSWORD=$ROOT\nDB_PASSWORD=kT9#vLq2!xZp8wRm\nDATABASE_URL=postgres://app:${P}@db/shop\n"
    assert dbaudit.check_env_lines(text, ".env") == []


def test_the_password_value_is_never_in_the_output():
    text = "POSTGRES_PASSWORD=changeme\nDATABASE_URL=mysql://root:toor@db/x\n--requirepass redis\n"
    out = json.dumps(dbaudit.check_env_lines(text, ".env") + dbaudit.check_compose_commands(text, "c.yml"))
    assert "changeme" not in out and "toor" not in out and "requirepass redis" not in out


def test_connection_strings():
    found = dbaudit.check_urls("URL=postgresql://postgres:postgres@db:5432/shop?sslmode=disable\nX=mongodb://app:Zk83hd82hdLLq@m/x\n", "a.env")
    assert rules(found) == ["no-tls", "superuser-app", "weak-password"] and all(f["line"] == 1 for f in found)


def test_pg_hba():
    text = """# comment trust
local all all trust
host all all 127.0.0.1/32 scram-sha-256
host all all 0.0.0.0/0 trust
host all all 10.0.0.0 255.0.0.0 password
hostssl all all 0.0.0.0/0 scram-sha-256
host all all ::/0 md5
host all all 0.0.0.0/0 reject
"""
    found = dbaudit.check_pg_hba(text, "pg_hba.conf")
    by_line = {}
    for f in found:
        by_line.setdefault(f["line"], []).append((f["rule"].replace("polyscan-db-", ""), f["severity"]))
    assert by_line[2] == [("pg-hba-trust", "medium")]
    assert 3 not in by_line and 8 not in by_line  # scram on localhost and reject are fine
    assert ("pg-hba-trust", "critical") in by_line[4]
    assert by_line[5] == [("pg-hba-cleartext", "medium")]
    assert by_line[6] == [("pg-hba-any-address", "medium")]  # hostssl: no "no TLS" finding
    assert {r for r, _ in by_line[7]} == {"pg-hba-md5", "pg-hba-any-address", "pg-hba-no-ssl"}


def test_server_configuration_files():
    assert rules(dbaudit.check_postgresql_conf("ssl = off\npassword_encryption = md5\nlisten_addresses = '*'\n#ssl = off\n", "p")) == ["listen-all", "pg-md5", "pg-ssl-off"]
    assert dbaudit.check_postgresql_conf("ssl = on\nlisten_addresses = 'localhost'\n", "p") == []
    assert rules(dbaudit.check_mysql_conf("[mysqld]\nskip-grant-tables\nlocal_infile=1\nbind-address = 0.0.0.0\nrequire_secure_transport = OFF\n", "m")) == [
        "listen-all", "mysql-local-infile", "mysql-no-tls", "mysql-skip-grant-tables"]  # fmt: skip
    assert rules(dbaudit.check_mongo_conf("security:\n  authorization: disabled\nnet:\n  bindIp: 0.0.0.0\n", "m")) == ["listen-all", "mongo-no-auth"]
    assert rules(dbaudit.check_redis_conf("protected-mode no\n", "r")) == ["redis-no-password", "redis-protected-mode-off"]
    assert dbaudit.check_redis_conf("requirepass 8hd82hDJ2k2jdLLs9\nprotected-mode yes\n", "r") == []
    assert rules(dbaudit.check_compose_commands("command: redis-server --protected-mode no --requirepass admin\ncommand: mongod --noauth\n", "c")) == [
        "mongo-no-auth", "redis-protected-mode-off", "weak-password"]  # fmt: skip


def test_walk_examples_excludes_and_nothing(tmp_path):
    assert dbaudit.main([str(tmp_path)]) == dbaudit.EXIT_NOTHING
    (tmp_path / ".env.example").write_text("POSTGRES_PASSWORD=changeme\n")
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf" / "pg_hba.conf").write_text("host all all 0.0.0.0/0 trust\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / ".env").write_text("POSTGRES_PASSWORD=postgres\n")
    found, checked = dbaudit.audit(tmp_path)
    assert checked == 2
    example = [f for f in found if f["file"] == ".env.example"][0]
    assert example["severity"] == "low" and "example/template" in example["message"]
    assert dbaudit.audit(tmp_path, ("conf",))[1] == 1


def test_parser_tool_and_threat_links(tmp_path, monkeypatch):
    text = json.dumps({"kind": "dbaudit", "files": 1, "findings": dbaudit.check_env_lines("POSTGRES_HOST_AUTH_METHOD=trust\nPGPASSWORD=root\n", ".env")})
    trust, weak = parse_dbaudit(text, "/p")
    assert (trust.tool, trust.severity, trust.category, trust.cwe) == ("db-config", Severity.CRITICAL, "config", "CWE-306")
    assert [a["id"] for a in threat_for([weak]).attack] == ["T1078", "T1110"]
    with pytest.raises(ValueError):
        parse_dbaudit("{}", "/p")
    tool = DbConfig()
    assert any(t.name == "db-config" for t in all_tools()) and tool.applies({})
    assert tool.local_cmd("x", ScanOptions(excludes=("a",)))[1:] == ["-m", "polyscan.dbaudit", "x", "--exclude", "a"]
    (tmp_path / ".env").write_text("PGPASSWORD=root\n")
    r = run_tool(tool, "local", tmp_path, ScanOptions(), 30)  # the real program, end to end
    assert r.status == OK and len(r.findings) == 1
    (tmp_path / ".env").unlink()
    assert run_tool(tool, "local", tmp_path, ScanOptions(), 30).status == SKIPPED
    assert subprocess.run([sys.executable, "-m", "polyscan.dbaudit", "--help"], capture_output=True).returncode == 0
