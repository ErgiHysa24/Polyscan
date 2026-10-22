"""Which network ports is THIS machine listening on, and who could reach them?

    polyscan ports [--expect 22,80,443]

It runs `ss -H -tulnp`, which only READS the list of listening sockets the operating system keeps.
Nothing is sent to the network and nothing is scanned: it cannot touch any other machine, so it
needs no authorization beyond being allowed to run commands on the machine it looks at.

What it can and cannot tell:
  * it sees what the machine LISTENS on and on which address: a database bound to 0.0.0.0 accepts
    connections from every network card, a database bound to 127.0.0.1 only from the machine itself;
  * it does NOT see the firewall: a port listening on every interface may still be blocked from
    outside. So the result is "this could be reachable", and the advice is to close it at the source.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

from .models import ERROR, OK, UNAVAILABLE, Finding, Severity, ToolResult
from .scanner import ScanResult

DEFAULT_EXPECTED = (22, 80, 443)  # what a web server is normally meant to show: SSH, HTTP, HTTPS

DB = "A database should be reachable only by the application that uses it, not by every network the machine is on."
ADMIN = "A remote-control service open to every network is a common way in; limit it to a management network or a VPN."
# port: (name, severity, why it matters)
SERVICES = {
    3306: ("MySQL/MariaDB", Severity.HIGH, DB),
    5432: ("PostgreSQL", Severity.HIGH, DB),
    1433: ("Microsoft SQL Server", Severity.HIGH, DB),
    1521: ("Oracle database", Severity.HIGH, DB),
    27017: ("MongoDB", Severity.HIGH, DB + " MongoDB installs without a login have been wiped by attackers many times."),
    6379: ("Redis", Severity.HIGH, "Redis normally has no login: whoever reaches it can read and change all its data."),
    11211: ("Memcached", Severity.HIGH, "Memcached has no login and has been abused for large attacks."),
    9200: ("Elasticsearch", Severity.HIGH, DB),
    5984: ("CouchDB", Severity.HIGH, DB),
    9042: ("Cassandra", Severity.HIGH, DB),
    2379: ("etcd", Severity.HIGH, "etcd holds cluster secrets and configuration."),
    2375: ("Docker API without encryption", Severity.CRITICAL, "Whoever reaches it controls Docker, which means control of the whole machine."),
    2376: ("Docker API (TLS)", Severity.MEDIUM, ADMIN),
    23: ("Telnet", Severity.HIGH, "Telnet sends passwords in clear text; use SSH."),
    21: ("FTP", Severity.MEDIUM, "FTP sends passwords in clear text; use SFTP."),
    3389: ("Remote Desktop (RDP)", Severity.HIGH, ADMIN),
    5900: ("VNC", Severity.HIGH, ADMIN),
    445: ("SMB file sharing", Severity.HIGH, "SMB is a frequent target; do not expose it outside a trusted network."),
    139: ("NetBIOS", Severity.MEDIUM, "Legacy file-sharing service; rarely needed."),
    111: ("rpcbind", Severity.MEDIUM, "Legacy service used to find other services; rarely needed."),
    161: ("SNMP", Severity.MEDIUM, "SNMP can reveal details of the machine and, with weak settings, change it."),
    15672: ("RabbitMQ management", Severity.MEDIUM, ADMIN),
}  # fmt: skip


@dataclass(frozen=True)
class Listener:
    proto: str  # tcp | udp
    host: str  # address it is bound to, as ss prints it without brackets or interface suffix
    port: int
    process: str  # "" if ss was not allowed to say

    @property
    def scope(self) -> str:
        """loopback: this machine only. all: every interface. interface: one specific address."""
        if self.host in ("*", ""):
            return "all"
        try:
            ip = ipaddress.ip_address(self.host)
        except ValueError:
            return "interface"
        if ip.is_loopback:
            return "loopback"
        return "all" if ip.is_unspecified else "interface"


PROCESS_RE = re.compile(r'\(\("([^"]*)"')


def parse_ss(text: str) -> tuple[list[Listener], int]:
    """(listeners, number of lines that could not be understood). Format of `ss -H -tulnp`:

        tcp  LISTEN 0 4096 127.0.0.54:53   0.0.0.0:*  users:(("name",pid=1,fd=3))
        tcp  LISTEN 0 128  [::]:22         [::]:*
        udp  UNCONN 0 0    127.0.0.53%lo:53 0.0.0.0:*
        tcp  LISTEN 0 511  *:80            *:*
    """
    out: list[Listener] = []
    bad = 0
    for line in text.splitlines():
        parts = line.split(None, 6)
        if not line.strip():
            continue
        if len(parts) < 6 or parts[0] not in ("tcp", "udp"):
            bad += 1
            continue
        host, sep, port = parts[4].rpartition(":")
        host = host.strip("[]").split("%", 1)[0]
        if not sep or not port.isdigit() or not 0 < int(port) < 65536:
            bad += 1
            continue
        m = PROCESS_RE.search(parts[6]) if len(parts) > 6 else None
        out.append(Listener(parts[0], host, int(port), m.group(1) if m else ""))
    return out, bad


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def findings_for(listeners: list[Listener], expected: tuple[int, ...] = DEFAULT_EXPECTED) -> list[Finding]:
    """One finding per (protocol, port, process) that is not limited to this machine."""
    groups: dict[tuple, list[Listener]] = {}
    for item in listeners:
        if item.scope != "loopback" and item.port not in expected:  # a port you declare is never reported
            groups.setdefault((item.proto, item.port, item.process), []).append(item)
    findings = []
    for (proto, port, process), items in sorted(groups.items()):
        addresses = ", ".join(sorted({"every interface" if i.scope == "all" else i.host for i in items}))
        by = f" (process: {process})" if process else ""
        where = f"{proto}/{port}"
        docker = " Docker published this port (docker-proxy): in Compose write `127.0.0.1:PORT:PORT` or remove the `ports:` entry." if "docker-proxy" in process else ""
        if port in SERVICES:
            name, severity, why = SERVICES[port]
            findings.append(
                Finding(
                    tool="ss", severity=severity, rule=f"exposed-{_slug(name)}",
                    message=f"{name} is listening on {addresses}{by}. {why} Bind it to 127.0.0.1 or to an internal network, "
                            f"or block the port with a firewall.{docker}",
                    file=where, line=0, category="runtime",
                )
            )  # fmt: skip
        else:
            findings.append(
                Finding(
                    tool="ss", severity=Severity.LOW, rule="unexpected-listener",
                    message=f"A service is listening on {addresses}{by}, and port {port} is not in the list of ports you expect "
                            f"({', '.join(map(str, expected))}). Check that it should be reachable; if not, bind it to 127.0.0.1 "
                            f"or block it with a firewall; if so, add it with --expect.{docker}",
                    file=where, line=0, category="runtime",
                )
            )  # fmt: skip
    return findings


def check(
    expected: tuple[int, ...] = DEFAULT_EXPECTED,
    run=None,
    platform: str | None = None,
    which=None,
) -> ScanResult:
    # Looked up here, not in the signature, so that a test (or a caller) can replace them.
    run = run or subprocess.run
    platform = sys.platform if platform is None else platform
    which = which or shutil.which
    result = ScanResult("this machine", {}, mode="local", kind="host")
    if not platform.startswith("linux"):
        result.tools.append(ToolResult("ss", UNAVAILABLE, "this check needs Linux (the ss program); run it on the server or VM"))
        return result
    if which("ss") is None:
        result.tools.append(ToolResult("ss", UNAVAILABLE, "ss is not installed (Linux package: iproute2)"))
        return result
    try:
        proc = run(["ss", "-H", "-tulnp"], capture_output=True, text=True, errors="replace", timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        result.tools.append(ToolResult("ss", ERROR, f"could not run ss: {exc}"))
        return result
    if proc.returncode != 0:
        text = " ".join((proc.stderr or proc.stdout or "no output").split())[-300:]
        result.tools.append(ToolResult("ss", ERROR, f"exit code {proc.returncode}: {text}"))
        return result
    listeners, bad = parse_ss(proc.stdout)
    if not listeners:
        # A real machine always has something listening; none means ss was blocked or its format changed.
        result.tools.append(ToolResult("ss", ERROR, f"no listening sockets understood ({bad} unreadable lines)"))
        return result
    detail = f"{len(listeners)} listening sockets" + (f"; {bad} lines not understood" if bad else "")
    if not any(item.process for item in listeners):
        detail += "; process names not shown (run as root to see them)"
    result.tools.append(ToolResult("ss", OK, detail, findings_for(listeners, expected)))
    return result
