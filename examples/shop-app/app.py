"""shop-app: DELIBERATELY INSECURE demo for polyscan. Do not deploy. See README.md."""

import hashlib
import os

import psycopg2
from flask import Flask, jsonify, redirect, request, session

app = Flask(__name__)
app.secret_key = "dev-secret-key-123456"  # planted: a secret in the code
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@db:5432/shop?sslmode=disable")

PAGE = "<!doctype html><html><head><title>{title}</title></head><body><h1>{title}</h1>{body}<p><a href='/'>Home</a></p></body></html>"


def db():
    return psycopg2.connect(DATABASE_URL)


@app.route("/")
def home():
    who = session.get("user")
    links = "<a href='/account'>Account</a> | <a href='/logout'>Log out</a>" if who else "<a href='/login'>Log in</a>"
    return PAGE.format(title="Demo shop", body=f"<p>{links} | <a href='/search?q=shoes'>Search</a> | <a href='/api/products'>API</a></p>")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        digest = hashlib.md5(request.form.get("password", "").encode()).hexdigest()  # planted: unsalted MD5
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT name FROM users WHERE name = %s AND password_md5 = %s", (request.form.get("username", ""), digest))
            row = cur.fetchone()
        if row:
            session["user"] = row[0]
            return redirect("/account")
        return PAGE.format(title="Log in", body="<p>Wrong user or password.</p>"), 401
    form = "<form method='POST' action='/login'><input name='username'><input type='password' name='password'><input type='submit' value='Log in'></form>"
    return PAGE.format(title="Log in", body=form)


@app.route("/account")
def account():
    if not session.get("user"):
        return redirect("/login")
    resp = app.make_response(PAGE.format(title="Account", body=f"<p>Signed in as {session['user']}.</p><p><a href='/orders'>Orders</a></p>"))
    resp.headers["X-Powered-By"] = "PHP/5.6.40"  # planted: a banner visible only after the login
    return resp


@app.route("/orders")
def orders():
    if not session.get("user"):
        return redirect("/login")
    return PAGE.format(title="Orders", body="<p>No orders yet.</p>")


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
    items = "".join(f"<li>{name}: {price}</li>" for name, price in rows) or "<li>No results.</li>"
    return PAGE.format(title="Search", body=f"<ul>{items}</ul>")


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
