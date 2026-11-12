"""The authenticator-app codes of the demo shop (examples/shop-app/totp.py), against the official RFC 6238 vectors."""

import base64
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("shop_totp", Path(__file__).parent.parent / "examples" / "shop-app" / "totp.py")
totp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(totp)

SECRET = base64.b32encode(b"12345678901234567890").decode()  # the RFC's test secret


@pytest.mark.parametrize("when, code", [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                                        (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")])  # fmt: skip
def test_rfc_6238_vectors(when, code):
    assert totp.code_at(SECRET, when // 30) == code  # the RFC lists 8 digits; these are their last 6


def test_window_replay_and_bad_input():
    now = 1_000_000
    step = totp.counter_now(now)
    good = totp.code_at(SECRET, step)
    assert totp.verify(SECRET, good, now=now) == step
    assert totp.verify(SECRET, f"{good[:3]} {good[3:]}", now=now) == step  # typed with a space, as apps show it
    assert totp.verify(SECRET, good, last_used=step, now=now) is None  # the same code cannot be used twice
    assert totp.verify(SECRET, totp.code_at(SECRET, step - 1), now=now) == step - 1  # a slow typist
    assert totp.verify(SECRET, totp.code_at(SECRET, step - 2), now=now) is None  # but not an old code
    for bad in ("", "12345", "1234567", "abcdef", None):
        assert totp.verify(SECRET, bad, now=now) is None


def test_new_secrets_are_random_base32_and_the_uri_is_what_apps_expect():
    a, b = totp.new_secret(), totp.new_secret()
    assert a != b and len(a) == 32 and base64.b32decode(a)
    uri = totp.uri(a, "bob smith")
    assert uri.startswith("otpauth://totp/demo-shop:bob%20smith?secret=" + a) and "period=30" in uri and "digits=6" in uri
