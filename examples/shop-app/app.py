"""shop-app: DELIBERATELY INSECURE demo for polyscan. Do not deploy. See README.md."""

import hashlib
import os

import io

import psycopg2
import segno
from flask import Flask, jsonify, redirect, request, session
from markupsafe import escape

import totp

app = Flask(__name__)
app.secret_key = "dev-secret-key-123456"  # planted: a secret in the code
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@db:5432/shop?sslmode=disable")

STYLE = """
:root{--bg:#f3f5f4;--card:#fbfcfb;--text:#14201c;--muted:#566660;--line:#c9d1cd;--accent:#0b6b57;--bad:#a3122a;
--mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,"DejaVu Sans Mono",monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0d1512;--card:#121d19;--text:#d5e2dc;--muted:#8da099;--line:#27352f;--accent:#5fd0a8;--bad:#ff6b81}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--mono)}
main{max-width:720px;margin:0 auto;padding:28px 18px 56px}
nav{display:flex;flex-wrap:wrap;gap:6px 18px;padding-bottom:12px;border-bottom:1px dashed var(--line);margin-bottom:26px}
nav b{margin-right:auto}nav b::before{content:"$ ";color:var(--muted)}
a{color:var(--accent)}a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
h1{font-size:24px;margin:0 0 14px}h1::before{content:"## ";color:var(--accent)}
form{display:grid;gap:12px;max-width:340px;padding:16px;background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent)}
label{display:grid;gap:4px;font-size:13px;color:var(--muted)}
input{font:inherit;padding:8px 10px;border:1px solid var(--line);background:var(--bg);color:var(--text)}
button{font:inherit;font-weight:700;padding:9px 12px;border:1px solid var(--accent);background:var(--accent);color:var(--bg);cursor:pointer}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line)}
td,th{text-align:left;padding:8px 11px;border-bottom:1px dashed var(--line)}td:last-child,th:last-child{text-align:right}
.err{color:var(--bad);border-left:3px solid var(--bad);padding-left:10px}.muted{color:var(--muted)}
.qr{background:#fff;padding:10px;display:inline-block;border:1px solid var(--line)}.qr svg{display:block}
code{background:var(--card);border:1px solid var(--line);padding:1px 5px;word-break:break-all}
footer{margin-top:40px;padding-top:12px;border-top:1px dashed var(--line);font-size:12px;color:var(--muted)}
"""
PAGE = ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>{title} - demo shop</title><style>" + STYLE.replace("{", "{{").replace("}", "}}") + "</style></head><body><main>"
        "<nav><b>demo-shop</b><a href='/'>Home</a><a href='/search?q=shoes'>Search</a><a href='/account'>Account</a></nav>"
        "<h1>{title}</h1>{body}<footer>Deliberately insecure demo for polyscan. Do not deploy.</footer></main></body></html>")



def db():
    return psycopg2.connect(DATABASE_URL)


def user_row(name):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT name, totp_secret, totp_last_step FROM users WHERE name = %s", (name,))
        return cur.fetchone()


def page(title, body, status=200):
    return PAGE.format(title=title, body=body), status


@app.route("/")
def home():
    who = session.get("user")
    state = f"<p>Signed in as <b>{escape(who)}</b>. <a href='/logout'>Log out</a></p>" if who else "<p><a href='/login'>Log in</a> to see your account.</p>"
    return page("Demo shop", state + "<p class='muted'>Try the <a href='/search?q=shoes'>search</a> or the <a href='/api/products'>product API</a>.</p>")


LOGIN_FORM = ("<form method='POST' action='/login'><label>User name<input name='username' autocomplete='username' required></label>"
              "<label>Password<input type='password' name='password' autocomplete='current-password' required></label>"
              "<button type='submit'>Log in</button></form>")  # fmt: skip
CODE_FORM = ("<form method='POST' action='{action}'><label>6-digit code from your authenticator app"
             "<input name='code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9 ]*' maxlength='7' required autofocus></label>"
             "<button type='submit'>{button}</button></form>")  # fmt: skip


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        digest = hashlib.md5(request.form.get("password", "").encode()).hexdigest()  # planted: unsalted MD5
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT name, totp_secret FROM users WHERE name = %s AND password_md5 = %s", (request.form.get("username", ""), digest))
            row = cur.fetchone()
        if not row:
            return page("Log in", "<p class='err'>Wrong user name or password.</p>" + LOGIN_FORM, 401)
        session.clear()
        if row[1]:  # this account has an authenticator app: the password alone is not enough
            session["pending"], session["tries"] = row[0], 0
            return redirect("/login/code")
        session["user"] = row[0]
        return redirect("/account")
    return page("Log in", LOGIN_FORM)


@app.route("/login/code", methods=["GET", "POST"])
def login_code():
    name = session.get("pending")
    row = user_row(name) if name else None
    if not row or not row[1]:
        return redirect("/login")
    form = CODE_FORM.format(action="/login/code", button="Verify")
    if request.method == "POST":
        session["tries"] = session.get("tries", 0) + 1
        if session["tries"] > 5:  # a 6-digit code must not be guessable by trying
            session.clear()
            return page("Log in", "<p class='err'>Too many wrong codes. Log in again.</p>" + LOGIN_FORM, 429)
        step = totp.verify(row[1], request.form.get("code", ""), row[2])
        if step is None:
            return page("Second step", "<p class='err'>That code is not valid. Codes change every 30 seconds and work once.</p>" + form, 401)
        with db() as conn, conn.cursor() as cur:
            cur.execute("UPDATE users SET totp_last_step = %s WHERE name = %s", (step, name))
        session.clear()
        session["user"] = name
        return redirect("/account")
    return page("Second step", f"<p>Password accepted for <b>{escape(name)}</b>. Now the code.</p>" + form)


@app.route("/account")
def account():
    if not session.get("user"):
        return redirect("/login")
    row = user_row(session["user"])
    two = ("<p>Authenticator app: <b>on</b>. <a href='/account/2fa'>Turn off</a></p>" if row and row[1]
           else "<p>Authenticator app: off. <a href='/account/2fa'>Turn on two-step login</a></p>")  # fmt: skip
    resp = app.make_response(PAGE.format(title="Account", body=f"<p>Signed in as <b>{escape(session['user'])}</b>.</p>{two}<p><a href='/orders'>Orders</a></p>"))
    resp.headers["X-Powered-By"] = "PHP/5.6.40"  # planted: a banner visible only after the login
    return resp


@app.route("/account/2fa", methods=["GET", "POST"])
def two_factor():
    name = session.get("user")
    if not name:
        return redirect("/login")
    row = user_row(name)
    enabled = bool(row[1])
    if enabled:  # turning it off needs a valid code: a stolen session alone must not be able to remove it
        form = CODE_FORM.format(action="/account/2fa", button="Turn off")
        if request.method == "POST":
            step = totp.verify(row[1], request.form.get("code", ""), row[2])
            if step is None:
                return page("Authenticator app", "<p class='err'>That code is not valid.</p>" + form, 401)
            with db() as conn, conn.cursor() as cur:
                cur.execute("UPDATE users SET totp_secret = NULL, totp_last_step = -1 WHERE name = %s", (name,))
            return redirect("/account")
        return page("Authenticator app", "<p>Two-step login is on. Enter a code to turn it off.</p>" + form)
    secret = session.get("new_secret") or totp.new_secret()
    session["new_secret"] = secret
    form = CODE_FORM.format(action="/account/2fa", button="Turn on")
    error = ""
    if request.method == "POST":
        step = totp.verify(secret, request.form.get("code", ""))
        if step is not None:  # the secret is saved only after the app has proved it knows it
            with db() as conn, conn.cursor() as cur:
                cur.execute("UPDATE users SET totp_secret = %s, totp_last_step = %s WHERE name = %s", (secret, step, name))
            session.pop("new_secret", None)
            return redirect("/account")
        error = "<p class='err'>That code is not valid. Scan the QR code again and type the current code.</p>"
    out = io.BytesIO()
    segno.make(totp.uri(secret, name), error="m").save(out, kind="svg", scale=4, border=2, xmldecl=False, svgns=True, nl=False)
    steps = (f"<ol><li>Open your authenticator app (Google Authenticator, Microsoft Authenticator, Authy...) and scan this code.</li></ol>"
             f"<div class='qr'>{out.getvalue().decode()}</div><p class='muted'>Cannot scan? Type this key in the app: <code>{secret}</code></p>"
             "<ol start='2'><li>Type the 6-digit code the app shows.</li></ol>")  # fmt: skip
    return page("Authenticator app", error + steps + form, 401 if error else 200)


@app.route("/orders")
def orders():
    if not session.get("user"):
        return redirect("/login")
    return page("Orders", "<p class='muted'>No orders yet.</p>")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT name, price FROM products WHERE name LIKE '%" + q + "%'")  # planted: SQL injection
        rows = cur.fetchall()
    items = "".join(f"<tr><td>{name}</td><td>{price}</td></tr>" for name, price in rows)
    table = f"<table><tr><th>Product</th><th>Price</th></tr>{items}</table>" if items else "<p class='muted'>Nothing matches. Try 'shoes'.</p>"
    form = "<form method='GET' action='/search'><label>Product name<input name='q'></label><button type='submit'>Search</button></form><br>"
    return page("Search", form + table)


@app.route("/api/products")
def api_products():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, name, price FROM products ORDER BY id")
        return jsonify([{"id": i, "name": n, "price": float(p)} for i, n, p in cur.fetchall()])


@app.route("/healthz")
def healthz():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1")
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # planted: debug mode, all interfaces
