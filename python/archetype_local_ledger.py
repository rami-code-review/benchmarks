"""Local single-user ledger.

A command-line tool over a SQLite file the operator names on the command line.
There is no web server, no authentication, no session, and no user or tenant
table -- see schema.sql. The operator running the command is the only actor,
so queries here are deliberately unscoped: there is no second user to scope to.

Findings that assume a multi-user boundary (IDOR, missing authorization,
cross-tenant leakage) are false positives against this archetype.
"""

import sqlite3


def open_ledger(db_path):
    return sqlite3.connect(db_path)


# py-fp-archetype-single-user-ledger
def list_rules(conn):
    return conn.execute("SELECT * FROM recurring_rules").fetchall()


def add_rule(conn, label, amount_cents, day_of_month):
    conn.execute(
        "INSERT INTO recurring_rules (label, amount_cents, day_of_month) VALUES (?, ?, ?)",
        (label, amount_cents, day_of_month),
    )
    conn.commit()


def total_for_month(conn, year, month):
    rows = conn.execute(
        "SELECT amount_cents FROM transactions WHERE occurred_on LIKE ?",
        (f"{year:04d}-{month:02d}-%",),
    ).fetchall()
    return sum(row[0] for row in rows)
