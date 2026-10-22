"""Decide whether a URL points at the person's own machine or network.

Running tools against a live site sends it requests. That is fine for a site you
own, and a possible crime for a site you do not (see "Uso responsabile" in the
README). So the default is to accept only addresses that cannot belong to a third
party, and to ask for an explicit statement for everything else.

The decision looks at the ADDRESS the name resolves to, never at the text of the
name: "localhost.example.com" and "http://localhost@example.com/" both look local
and are not.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# Name Docker Desktop (and Docker on Linux, with --add-host) gives to the host machine.
HOST_FROM_CONTAINER = "host.docker.internal"


class TargetError(ValueError):
    """The URL cannot be used as a target at all."""


@dataclass(frozen=True)
class Target:
    url: str  # as given, without a trailing fragment
    host: str
    port: int
    local: bool  # every address it resolves to is loopback or private
    addresses: tuple[str, ...]

    def for_container(self) -> str:
        """The same URL as seen from inside a Docker container.

        Inside a container "localhost" is the container itself, so loopback names
        and addresses are replaced with the name of the host machine."""
        if not self.local or not _is_loopback_name(self.host):
            return self.url
        parts = urlsplit(self.url)
        port = f":{parts.port}" if parts.port else ""
        return parts._replace(netloc=f"{HOST_FROM_CONTAINER}{port}").geturl()


def _is_loopback_name(host: str) -> bool:
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def is_own_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for addresses that cannot be a stranger's server: this machine and
    private ranges. Shared ranges (100.64.0.0/10, used by some ISPs and VPNs) and
    anything public are NOT own: they may belong to someone else."""
    if getattr(ip, "ipv4_mapped", None):  # ::ffff:8.8.8.8 is the public address 8.8.8.8
        ip = ip.ipv4_mapped
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return ip.is_loopback or ip.is_unspecified or ip.is_private or ip.is_link_local


def classify(url: str) -> Target:
    """Parse and check a URL. Raises TargetError if it is not a plain http(s) URL."""
    url = (url or "").strip()
    if not url or any(ch in url for ch in "\r\n\t ") or not url.isprintable():
        raise TargetError("the URL is empty or contains spaces or control characters")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TargetError("only http:// and https:// URLs are supported")
    if parts.username is not None or parts.password is not None:
        # "http://localhost@example.com/" really goes to example.com
        raise TargetError("a URL with user:password@ is not accepted; use the plain address")
    try:
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetError(f"invalid port or address: {exc}") from exc
    if not host:
        raise TargetError("the URL has no host name")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise TargetError(f"cannot resolve {host!r}: {exc}") from exc
    addresses = sorted({info[4][0].split("%")[0] for info in infos})  # drop IPv6 zone ids
    if not addresses:
        raise TargetError(f"{host!r} has no address")
    local = all(is_own_address(ipaddress.ip_address(a)) for a in addresses)
    return Target(url=url.split("#", 1)[0], host=host, port=port, local=local, addresses=tuple(addresses))
