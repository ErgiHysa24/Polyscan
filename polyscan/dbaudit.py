"""Database configuration audit: PostgreSQL, MySQL/MariaDB, MongoDB and Redis, as they are configured
in the project (Docker environment variables, .env files, connection strings, and the databases' own
configuration files).

    python -m polyscan.dbaudit FOLDER [--exclude PATTERN]...   -> JSON on stdout (exit 4: nothing to check)

What it looks for (each check names its CWE):

  no authentication     POSTGRES_HOST_AUTH_METHOD=trust, MYSQL_ALLOW_EMPTY_PASSWORD, pg_hba "trust",
                        skip-grant-tables, MongoDB authorization disabled, Redis protected-mode off
  weak/default password POSTGRES_PASSWORD=postgres, MYSQL_ROOT_PASSWORD=root, requirepass "redis"...
                        (the value is compared, NEVER printed)
  cleartext            pg_hba "password" method, sslmode=disable in a connection string, ssl = off
  weak hashing          pg_hba "md5", password_encryption = md5 (SCRAM-SHA-256 is the current default)
  too much privilege    the application connects as the superuser (postgres, root, sa)
  listening everywhere  listen_addresses='*', bind-address=0.0.0.0, bindIp 0.0.0.0 (a hint, not a
                        verdict: it is normal inside a container, so it is LOW)
  pg_hba open to all    host lines for 0.0.0.0/0, ::/0 or "all" addresses
  LOAD DATA LOCAL       local-infile = 1 (lets a compromised client read files)

It only reads text files; nothing connects to a database. The rules are written so that a value
coming from a variable (`${POSTGRES_PASSWORD}`) is never judged: polyscan cannot see it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .scanner import is_excluded

EXIT_NOTHING = 4
NEVER_ENTER = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "target", "build", "dist"}
MAX_FILE = 512 * 1024

# Values that are defaults, examples or guessable. Compared case-insensitively; never printed.
WEAK = {
    "", "postgres", "password", "passw0rd", "root", "admin", "administrator", "123456", "12345678", "1234", "changeme",
    "change_me", "secret", "test", "example", "mysql", "mariadb", "mongo", "mongodb", "redis", "pass", "default",
    "qwerty", "letmein", "toor", "sa", "user", "guest", "demo", "db", "database", "pwd",
}  # fmt: skip
PASSWORD_VARS = {
    "POSTGRES_PASSWORD", "PGPASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "MARIADB_ROOT_PASSWORD",
    "MARIADB_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD", "REDIS_PASSWORD", "DB_PASSWORD", "DATABASE_PASSWORD",
}  # fmt: skip
SUPERUSERS = {"postgres", "root", "sa", "admin"}
TRUE = {"1", "yes", "true", "on"}

COMPOSE = re.compile(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$", re.I)
ENV = re.compile(r"^\.env(\.[\w-]+)?$|^[\w-]+\.env$", re.I)
CONF_NAMES = {"pg_hba.conf": "pg_hba", "postgresql.conf": "postgresql", "my.cnf": "mysql", "mysqld.cnf": "mysql",
              "mariadb.cnf": "mysql", "server.cnf": "mysql", "mongod.conf": "mongo", "redis.conf": "redis"}  # fmt: skip
URL = re.compile(r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://([^:@/\s'\"]+)(?::([^@/\s'\"]*))?@[^\s'\"]+", re.I)
ASSIGN = re.compile(r"""^\s*(?:-\s*)?(?:export\s+)?["']?([A-Z][A-Z0-9_]*)["']?\s*[:=]\s*(.*?)\s*$""")


def finding(rule, severity, message, file, line, cwe):
    return {"rule": f"polyscan-db-{rule}", "severity": severity, "message": message, "file": file, "line": line, "cwe": cwe}


def _value(raw: str) -> str | None:
    """The literal value of an assignment, or None when it comes from a variable or is not a plain value."""
    v = raw.strip()
    v = re.sub(r"\s+#.*$", "", v)  # trailing comment
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    if "$" in v or v.startswith(("{", "[", "!")):
        return None
    return v


def check_env_lines(text: str, path: str) -> list[dict]:
    """KEY=value or KEY: value lines (compose environment blocks, .env files)."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        m = ASSIGN.match(line)
        if not m:
            continue
        key, value = m.group(1).upper(), _value(m.group(2))
        if value is None:
            continue
        low = value.lower()
        if key == "POSTGRES_HOST_AUTH_METHOD" and low == "trust":
            out.append(finding("postgres-trust", "critical", "PostgreSQL accepts connections WITHOUT a password (POSTGRES_HOST_AUTH_METHOD=trust).", path, n, "CWE-306"))
        elif key in ("MYSQL_ALLOW_EMPTY_PASSWORD", "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD", "MARIADB_ALLOW_EMPTY_PASSWORD") and low in TRUE:
            out.append(finding("mysql-empty-password", "critical", f"The database root user may have NO password ({key}).", path, n, "CWE-306"))
        elif key == "ALLOW_EMPTY_PASSWORD" and low in TRUE:
            out.append(finding("empty-password-allowed", "critical", "The database allows an empty password (ALLOW_EMPTY_PASSWORD).", path, n, "CWE-306"))
        elif key in PASSWORD_VARS and low in WEAK:
            what = "empty" if not value else "a default or guessable value"
            out.append(finding("weak-password", "high", f"{key} is {what}. Use a long random password from a secret store.", path, n, "CWE-1393"))
        elif key in ("POSTGRES_USER", "MYSQL_USER", "DB_USER", "DATABASE_USER") and low in SUPERUSERS and key != "POSTGRES_USER":
            out.append(finding("superuser-app", "medium", f"{key}={value}: the application should use its own user with only the rights it needs.", path, n, "CWE-250"))
    out += check_urls(text, path)
    return out


def check_urls(text: str, path: str) -> list[dict]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for m in URL.finditer(line):
            scheme, user, password = m.group(1).lower(), m.group(2), m.group(3)
            if "$" in m.group(0):
                continue
            if user.lower() in SUPERUSERS:
                out.append(finding("superuser-app", "medium", f"A {scheme} connection string logs in as the superuser '{user}': give the application its own least-privilege user.", path, n, "CWE-250"))
            if password is not None and password.lower() in WEAK:
                out.append(finding("weak-password", "high", f"A {scheme} connection string uses a default or guessable password.", path, n, "CWE-1393"))
            if re.search(r"[?&](sslmode=disable|ssl=false|tls=false|useSSL=false)", m.group(0), re.I):
                out.append(finding("no-tls", "medium", f"A {scheme} connection string turns encryption off: credentials and data travel in clear text.", path, n, "CWE-319"))
    return out


def check_pg_hba(text: str, path: str) -> list[dict]:
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        kind = parts[0].lower()
        if kind == "local":
            method = parts[3].lower() if len(parts) > 3 else ""
            address = "local socket"
        elif kind.startswith("host") and len(parts) >= 5:
            address = parts[3]
            # "host db user 10.0.0.0 255.0.0.0 md5": address and netmask in two fields
            method = (parts[5] if re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[4]) and len(parts) > 5 else parts[4]).lower()
        else:
            continue
        everyone = address in ("0.0.0.0/0", "::/0", "all", "0.0.0.0", "*")
        if method == "trust":
            sev = "critical" if kind.startswith("host") and everyone else ("high" if kind.startswith("host") else "medium")
            out.append(finding("pg-hba-trust", sev, f"pg_hba.conf lets {address} connect WITHOUT a password (method trust).", path, n, "CWE-306"))
        elif method == "password":
            out.append(finding("pg-hba-cleartext", "medium", "pg_hba.conf method 'password' sends the password in clear text; use scram-sha-256.", path, n, "CWE-319"))
        elif method == "md5":
            out.append(finding("pg-hba-md5", "low", "pg_hba.conf uses md5 password hashing; scram-sha-256 is stronger and the PostgreSQL default.", path, n, "CWE-328"))
        if everyone and kind.startswith("host") and method not in ("reject", "trust"):
            out.append(finding("pg-hba-any-address", "medium", f"pg_hba.conf accepts logins from any address ({address}); restrict it to the application's network.", path, n, "CWE-1327"))
        if kind == "host" and everyone and method not in ("reject",):
            out.append(finding("pg-hba-no-ssl", "low", "pg_hba.conf 'host' line from any address also accepts connections without TLS; use 'hostssl'.", path, n, "CWE-319"))
    return out


def _settings(text: str):
    """key = value lines of an ini-like file (postgresql.conf, my.cnf, redis.conf, YAML-ish mongod.conf)."""
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z_][\w.-]*)\s*(?:=|:|\s)\s*(.*)$", line)
        if m:
            yield n, m.group(1).lower().replace("-", "_"), m.group(2).strip().strip("'\"").lower()
        elif line and re.match(r"^[A-Za-z_][\w-]*$", line):
            yield n, line.lower().replace("-", "_"), ""


def check_postgresql_conf(text: str, path: str) -> list[dict]:
    out = []
    for n, key, value in _settings(text):
        if key == "ssl" and value in ("off", "false", "0"):
            out.append(finding("pg-ssl-off", "medium", "postgresql.conf: ssl = off, connections are not encrypted.", path, n, "CWE-319"))
        elif key == "password_encryption" and value == "md5":
            out.append(finding("pg-md5", "low", "postgresql.conf: password_encryption = md5; use scram-sha-256.", path, n, "CWE-328"))
        elif key == "listen_addresses" and value in ("*", "0.0.0.0", "::"):
            out.append(finding("listen-all", "low", "postgresql.conf listens on every network interface; fine inside a container, otherwise limit it.", path, n, "CWE-1327"))
    return out


def check_mysql_conf(text: str, path: str) -> list[dict]:
    out = []
    for n, key, value in _settings(text):
        if key == "skip_grant_tables":
            out.append(finding("mysql-skip-grant-tables", "critical", "skip-grant-tables: MySQL accepts EVERY login with full privileges.", path, n, "CWE-306"))
        elif key == "local_infile" and value in TRUE:
            out.append(finding("mysql-local-infile", "medium", "local-infile = 1: LOAD DATA LOCAL can be abused to read files from clients.", path, n, "CWE-200"))
        elif key == "bind_address" and value in ("0.0.0.0", "*", "::"):
            out.append(finding("listen-all", "low", "MySQL bind-address listens on every interface; fine inside a container, otherwise limit it.", path, n, "CWE-1327"))
        elif key == "require_secure_transport" and value in ("off", "0", "false"):
            out.append(finding("mysql-no-tls", "medium", "require_secure_transport = OFF: clients may connect without encryption.", path, n, "CWE-319"))
    return out


def check_mongo_conf(text: str, path: str) -> list[dict]:
    out = []
    for n, key, value in _settings(text):
        if key == "authorization" and value == "disabled":
            out.append(finding("mongo-no-auth", "critical", "mongod.conf: authorization disabled, anyone who can connect can read and change everything.", path, n, "CWE-306"))
        elif key in ("bindip", "bind_ip") and ("0.0.0.0" in value or value == "*"):
            out.append(finding("listen-all", "low", "mongod.conf binds every interface; fine inside a container, otherwise limit it.", path, n, "CWE-1327"))
    return out


def check_redis_conf(text: str, path: str) -> list[dict]:
    out, has_pass = [], False
    for n, key, value in _settings(text):
        if key == "protected_mode" and value == "no":
            out.append(finding("redis-protected-mode-off", "high", "redis.conf: protected-mode no; without a password Redis answers anyone who can reach it.", path, n, "CWE-306"))
        elif key == "requirepass":
            has_pass = True
            if value in WEAK:
                out.append(finding("weak-password", "high", "redis.conf: requirepass is a default or guessable value.", path, n, "CWE-1393"))
    if not has_pass:
        out.append(finding("redis-no-password", "medium", "redis.conf sets no requirepass (and no ACL file was checked): Redis may have no password.", path, 0, "CWE-306"))
    return out


def check_compose_commands(text: str, path: str) -> list[dict]:
    """Flags passed to the database on the command line of a compose service."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if re.search(r"--protected-mode\s+no\b", line):
            out.append(finding("redis-protected-mode-off", "high", "Redis is started with --protected-mode no.", path, n, "CWE-306"))
        if re.search(r"--skip-grant-tables\b", line):
            out.append(finding("mysql-skip-grant-tables", "critical", "MySQL is started with --skip-grant-tables: every login has full privileges.", path, n, "CWE-306"))
        if re.search(r"--noauth\b", line):
            out.append(finding("mongo-no-auth", "critical", "MongoDB is started with --noauth.", path, n, "CWE-306"))
        m = re.search(r"--requirepass\s+(\S+)", line)
        if m and "$" not in m.group(1) and m.group(1).strip("'\"").lower() in WEAK:
            out.append(finding("weak-password", "high", "Redis --requirepass is a default or guessable value.", path, n, "CWE-1393"))
    return out


def audit(root: Path, excludes: tuple[str, ...] = ()) -> tuple[list[dict], int]:
    """(findings, number of files checked)."""
    findings, checked = [], 0
    for here, dirs, files in os.walk(root, followlinks=False):
        rel_dir = Path(here).relative_to(root).as_posix()
        dirs[:] = sorted(d for d in dirs if d not in NEVER_ENTER and not is_excluded(f"{rel_dir}/{d}".removeprefix("./"), excludes))
        for name in sorted(files):
            rel = f"{rel_dir}/{name}".removeprefix("./")
            if is_excluded(rel, excludes):
                continue
            kind = CONF_NAMES.get(name.lower())
            if not kind and COMPOSE.match(name):
                kind = "compose"
            elif not kind and ENV.match(name):
                kind = "env"
            if not kind:
                continue
            p = Path(here) / name
            try:
                if p.is_symlink() or p.stat().st_size > MAX_FILE:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            checked += 1
            if kind == "compose":
                findings += check_env_lines(text, rel) + check_compose_commands(text, rel)
            elif kind == "env":
                findings += check_env_lines(text, rel)
            elif kind == "pg_hba":
                findings += check_pg_hba(text, rel)
            elif kind == "postgresql":
                findings += check_postgresql_conf(text, rel)
            elif kind == "mysql":
                findings += check_mysql_conf(text, rel)
            elif kind == "mongo":
                findings += check_mongo_conf(text, rel)
            elif kind == "redis":
                findings += check_redis_conf(text, rel)
    # Example/template files hold placeholders on purpose: still worth a look, but not an alarm.
    for f in findings:
        if re.search(r"example|sample|template|\.dist\b", f["file"], re.I) and f["severity"] in ("critical", "high", "medium"):
            f["severity"] = "low"
            f["message"] += " (example/template file: make sure the real configuration does not copy it)"
    # one line can trigger the same rule twice (environment list + connection string): keep one
    unique, seen = [], set()
    for f in findings:
        k = (f["rule"], f["file"], f["line"])
        if k not in seen:
            seen.add(k)
            unique.append(f)
    return unique, checked


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="polyscan.dbaudit")
    p.add_argument("folder")
    p.add_argument("--exclude", action="append", default=[])
    args = p.parse_args(argv)
    findings, checked = audit(Path(args.folder).resolve(), tuple(args.exclude))
    if not checked:
        print("no database configuration found (compose files, .env, pg_hba.conf, postgresql.conf, my.cnf, mongod.conf, redis.conf)", file=sys.stderr)
        return EXIT_NOTHING
    json.dump({"kind": "dbaudit", "files": checked, "findings": findings}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
