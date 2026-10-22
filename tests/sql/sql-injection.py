import sqlite3

conn = sqlite3.connect("x.db")


def concat(name):
    cur = conn.cursor()
    # ruleid: polyscan-sql-python
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")


def fstring(name):
    cur = conn.cursor()
    # ruleid: polyscan-sql-python
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")


def percent(name):
    cur = conn.cursor()
    # ruleid: polyscan-sql-python
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)


def format_call(name):
    cur = conn.cursor()
    # ruleid: polyscan-sql-python
    cur.execute("DELETE FROM users WHERE name = '{}'".format(name))


def through_a_variable(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur = conn.cursor()
    # ruleid: polyscan-sql-python
    cur.execute(query)


def parameterized(name):
    cur = conn.cursor()
    # ok: polyscan-sql-python
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))


def constant_only():
    cur = conn.cursor()
    # ok: polyscan-sql-python
    cur.execute("SELECT * FROM users")


def constants_joined():
    cur = conn.cursor()
    # ok: polyscan-sql-python
    cur.execute("SELECT * FROM " "users")


def not_sql(a, b):
    # ok: polyscan-sql-python
    print("total: " + a + b)
