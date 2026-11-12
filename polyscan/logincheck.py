"""Proves that a form login works BEFORE the scan, so that an anonymous scan is never reported as an
authenticated one.

Found by testing for real: with a wrong password ZAP's own check passed, because the protected page
redirected to the login page, and the login page answers 200. So polyscan checks by itself, and never
follows redirects:

  1. without logging in, the check page must NOT answer 200 (otherwise it proves nothing);
  2. the form is posted with the user name and password; the cookies of the answer are kept;
  3. with those cookies, the check page must answer 200.

Only the standard library; the password goes in the POST body to the login URL (same site as the
target, checked by the caller) and nowhere else. A login form that needs a one-time token (anti-CSRF)
cannot be automated this way: the check fails and says so.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

TIMEOUT = 20


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D102 - returning None stops the redirect
        return None


def _opener(jar: CookieJar | None = None):
    handlers = [_NoRedirect()]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


def _status(opener, url: str, data: bytes | None = None) -> int:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "polyscan-login-check"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:  # noqa: S310 - http(s) URL of the site under test
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code  # 301/302/401/403...: an answer, not a failure


def verify(login_url: str, check_url: str, user: str, password: str, user_field: str = "username",
           password_field: str = "password", make_opener=_opener) -> str:  # fmt: skip
    """Empty text when the login works, otherwise the reason (never containing the password)."""
    for url in (login_url, check_url):
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            return "the login and check URLs must be http or https"
    try:
        anonymous = _status(make_opener(None), check_url)
        if anonymous == 200:
            return (f"the check page answers 200 without logging in, so it cannot prove a login "
                    f"(choose a page that only a logged-in user can open)")  # fmt: skip
        jar = CookieJar()
        opener = make_opener(jar)
        body = urllib.parse.urlencode({user_field: user, password_field: password}).encode()
        posted = _status(opener, login_url, body)
        after = _status(opener, check_url)
    except (OSError, ValueError) as exc:
        return f"could not reach the site to check the login: {type(exc).__name__}"
    if after != 200:
        return (f"the login did not work: after posting the form (answer {posted}) the check page still answers {after}, "
                "not 200. Check the user name, the password, the field names (--login-user-field, --login-password-field); "
                "a form with a one-time anti-CSRF token cannot be used this way")  # fmt: skip
    return ""
