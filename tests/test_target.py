import socket

import pytest

from polyscan.target import TargetError, classify


@pytest.fixture
def dns(monkeypatch):
    """Fake name resolution, so the tests never touch the network."""
    table = {}

    def fake(host, port, type=0, **kwargs):
        if host in table:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
        try:  # literal IP addresses resolve to themselves
            socket.inet_pton(socket.AF_INET, host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (host, port, 0, 0))]
        except OSError:
            raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return table


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:5000", "http://127.1.2.3/", "http://[::1]:8000/app", "http://0.0.0.0:8080",
        "http://10.1.2.3", "http://172.16.5.5:3000", "http://192.168.1.50/login", "http://169.254.10.10",
    ],
)  # fmt: skip
def test_own_addresses_are_local(dns, url):
    assert classify(url).local is True


def test_localhost_name_is_local(dns):
    dns["localhost"] = ["127.0.0.1"]
    t = classify("http://localhost:5000/path?x=1#frag")
    assert t.local and t.port == 5000 and t.url == "http://localhost:5000/path?x=1"  # fragment dropped


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "100.64.1.1", "172.32.0.1", "192.169.0.1", "1.1.1.1"])
def test_public_and_shared_addresses_are_remote(dns, ip):
    assert classify(f"http://{ip}/").local is False


def test_a_name_that_looks_local_but_resolves_to_a_public_address_is_remote(dns):
    dns["localhost.example.com"] = ["93.184.216.34"]
    dns["internal-looking.test"] = ["93.184.216.34"]
    assert classify("http://localhost.example.com").local is False
    assert classify("https://internal-looking.test").local is False


def test_a_name_resolving_to_a_private_address_is_local(dns):
    dns["myapp.lan"] = ["192.168.1.20"]
    assert classify("http://myapp.lan").local is True


def test_mixed_addresses_count_as_remote(dns):
    """If ANY address is public the site may be someone else's."""
    dns["both.test"] = ["127.0.0.1", "93.184.216.34"]
    assert classify("http://both.test").local is False


@pytest.mark.parametrize(
    "url",
    ["http://localhost@93.184.216.34/", "http://127.0.0.1:80@example.com/", "https://user:pw@localhost/"],
)
def test_user_info_tricks_are_refused(dns, url):
    with pytest.raises(TargetError, match="user:password@"):
        classify(url)


def test_the_host_of_a_user_info_trick_is_not_what_it_seems_even_without_the_refusal(dns):
    """Documents why the refusal exists: urlsplit says the host is the part after @."""
    from urllib.parse import urlsplit

    assert urlsplit("http://localhost@93.184.216.34/").hostname == "93.184.216.34"
    assert urlsplit("http://93.184.216.34#@localhost/").hostname == "93.184.216.34"
    assert classify("http://93.184.216.34#@localhost/").local is False


def test_ipv4_mapped_ipv6_does_not_hide_a_public_address(dns):
    assert classify("http://[::ffff:8.8.8.8]/").local is False
    assert classify("http://[::ffff:127.0.0.1]/").local is True


@pytest.mark.parametrize("url", ["ftp://localhost/", "file:///etc/passwd", "javascript:alert(1)", "localhost:5000", "//localhost"])
def test_only_http_and_https_are_accepted(dns, url):
    with pytest.raises(TargetError):
        classify(url)


@pytest.mark.parametrize("url", ["", "   ", "http://", "http://localhost:99999", "http://local host/", "http://localhost/\nHost: x"])
def test_malformed_urls_are_refused(dns, url):
    with pytest.raises(TargetError):
        classify(url)


def test_unresolvable_name_is_an_error_not_a_guess(dns):
    with pytest.raises(TargetError, match="cannot resolve"):
        classify("http://does-not-exist.invalid/")


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://localhost:5000/a?b=1", "http://host.docker.internal:5000/a?b=1"),
        ("http://127.0.0.1:8080", "http://host.docker.internal:8080"),
        ("https://localhost", "https://host.docker.internal"),
        ("http://[::1]:3000/x", "http://host.docker.internal:3000/x"),
    ],
)
def test_loopback_urls_are_rewritten_for_the_container(dns, url, expected):
    dns["localhost"] = ["127.0.0.1"]
    assert classify(url).for_container() == expected


def test_other_addresses_are_not_rewritten_for_the_container(dns):
    assert classify("http://192.168.1.20:8000/x").for_container() == "http://192.168.1.20:8000/x"
    assert classify("http://93.184.216.34/").for_container() == "http://93.184.216.34/"
