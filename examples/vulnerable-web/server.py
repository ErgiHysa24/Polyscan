"""A tiny web site with deliberate weaknesses, to try `polyscan dast` on.

DO NOT DEPLOY. It has no real functionality; it only behaves like a careless site:
no security headers, a cookie without protective flags, a form without an
anti-CSRF token, a password field that allows autocomplete, and a server banner
that shows its version. A passive scan finds these without attacking anything.

    python server.py                      # http://127.0.0.1:8000, this computer only
    python server.py --host 0.0.0.0       # needed when a Docker container must reach it on Linux
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = b"""<!doctype html>
<html><head><title>Demo shop</title></head>
<body>
  <h1>Demo shop</h1>
  <p><a href="/login">Log in</a> | <a href="/search?q=shoes">Search</a> | <a href="/about">About</a></p>
  <script src="/static/app.js"></script>
</body></html>
"""

LOGIN = b"""<!doctype html>
<html><head><title>Log in</title></head>
<body>
  <h1>Log in</h1>
  <form method="POST" action="/login">
    <input type="text" name="user">
    <input type="password" name="password">
    <input type="submit" value="Log in">
  </form>
  <p><a href="/">Home</a></p>
</body></html>
"""

ABOUT = b"<!doctype html><html><head><title>About</title></head><body><h1>About</h1><p><a href=\"/\">Home</a></p></body></html>\n"
JS = b"console.log('demo');\n"


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, content_type: str = "text/html; charset=utf-8", cookie: bool = False):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", "session=abc123; Path=/")  # no HttpOnly, Secure or SameSite
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (name required by http.server)
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(HOME, cookie=True)
        elif path == "/login":
            self._send(LOGIN)
        elif path == "/search":
            self._send(b"<!doctype html><html><head><title>Search</title></head><body><p>No results.</p><a href=\"/\">Home</a></body></html>\n")
        elif path == "/about":
            self._send(ABOUT)
        elif path == "/static/app.js":
            self._send(JS, "application/javascript")
        else:
            self.send_error(404)

    def do_POST(self):  # noqa: N802
        self._send(b"<!doctype html><html><body><p>Wrong password.</p><a href=\"/login\">Back</a></body></html>\n")

    def log_message(self, fmt, *args):  # keep the console quiet
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Demo site on http://{args.host}:{args.port}  (Ctrl+C to stop)", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
