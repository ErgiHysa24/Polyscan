"""Time-based one-time passwords (RFC 6238), the 6-digit codes of authenticator apps.

How it works, in four lines:
  * the site and the phone share a random SECRET (shown once, as a QR code);
  * both count how many 30-second steps have passed since 1970 (the "counter");
  * both compute HMAC-SHA1(secret, counter) and cut 6 digits out of it (RFC 4226 "dynamic truncation");
  * same secret + same time = same code, with no network on the phone.

Only the standard library. This part of the demo is written to be CORRECT (it is the control being
shown), unlike the deliberately weak parts of the application.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30  # seconds a code lasts
DIGITS = 6


def new_secret() -> str:
    """160 random bits, written in base32 (the alphabet authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F  # the last 4 bits say where to cut
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def counter_now(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def verify(secret: str, code: str, last_used: int = -1, now: float | None = None) -> int | None:
    """The counter of the matching step, or None.

    One step before and after the current one is accepted (clocks are never perfectly in sync). A step
    that is not newer than `last_used` is refused, so a code seen over someone's shoulder cannot be
    typed a second time. The comparison takes the same time whether the code is right or wrong."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != DIGITS:
        return None
    current = counter_now(now)
    for counter in (current - 1, current, current + 1):
        if counter > last_used and hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def uri(secret: str, account: str, issuer: str = "demo-shop") -> str:
    """What the QR code contains: the app reads the secret and the labels from it."""
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"
