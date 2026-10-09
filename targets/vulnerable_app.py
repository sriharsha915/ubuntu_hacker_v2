#!/usr/bin/env python3
"""
targets/vulnerable_app.py — a DELIBERATELY VULNERABLE practice target.

  ####################################################################
  #  INTENTIONALLY INSECURE. localhost ONLY. NEVER expose this.      #
  #  It exists so you can watch the attack loop win against a safe,  #
  #  self-owned target (like DVWA / Juice Shop, but 120 lines).      #
  ####################################################################

Vulnerabilities on purpose:
  * GET  /            login form
  * POST /login       SQL injection (string-concatenated query)   -> sqli-login
  * GET  /search?q=   reflected XSS (q echoed unescaped), with a
                      30-char length guard that forces the loop to
                      shorten its payload                          -> reflected-xss

Credentials seeded: admin / s3cr3t  (and user / password123)

Run:  python3 targets/vulnerable_app.py
"""

from __future__ import annotations

import os
import sqlite3
import threading

try:
    from flask import Flask, request, session, redirect, Response
except Exception:  # pragma: no cover
    raise SystemExit(
        "Flask is required for the demo target. Install it:\n"
        "    pip install flask\n"
        "or run scripts/install.sh"
    )

SEARCH_MAXLEN = 30  # short on purpose: long payloads get rejected -> [RECTIFY]

app = Flask(__name__)
app.secret_key = "demo-only-not-secret"

# A single shared in-memory DB guarded by a lock (demo-grade concurrency).
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db_lock = threading.Lock()


def _init_db() -> None:
    with _db_lock:
        _db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT
            );
            DELETE FROM users;
            INSERT INTO users (username, password) VALUES ('admin', 's3cr3t');
            INSERT INTO users (username, password) VALUES ('user', 'password123');
            """
        )
        _db.commit()


PAGE = """<!doctype html>
<html><head><title>{title}</title>
<style>body{{font-family:system-ui;margin:3rem;max-width:40rem}}
.warn{{background:#fee;border:1px solid #c00;padding:.6rem;color:#900;border-radius:6px}}
input,button{{font-size:1rem;padding:.4rem;margin:.2rem 0}}</style></head>
<body>
<p class="warn">⚠ Intentionally vulnerable demo app — localhost only.</p>
{body}
</body></html>"""


def render(title: str, body: str, status: int = 200) -> Response:
    return Response(PAGE.format(title=title, body=body), status=status, mimetype="text/html")


LOGIN_FORM = """
<h1>Login</h1>
<form method="post" action="/login">
  <div><input name="username" placeholder="username" autocomplete="off"></div>
  <div><input name="password" type="password" placeholder="password" autocomplete="off"></div>
  <div><button type="submit">Sign in</button></div>
</form>
"""


@app.route("/")
def index() -> Response:
    if session.get("user"):
        return redirect("/dashboard")
    return render("Login", LOGIN_FORM)


@app.route("/login", methods=["POST"])
def login() -> Response:
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE ON PURPOSE: never do this in real code.
    query = (
        "SELECT username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        with _db_lock:
            row = _db.execute(query).fetchone()
    except sqlite3.Error as exc:
        # Error-based SQLi: the engine error is reflected to the client.
        body = (
            f"<h1>Database error</h1><pre>sqlite3.OperationalError: {exc}</pre>"
            f"<p><a href='/'>back</a></p>"
        )
        return render("Error", body, status=500)

    if row:
        session["user"] = row[0]
        return redirect("/dashboard")
    return render("Login failed", "<h1>Invalid credentials</h1>" + LOGIN_FORM, status=401)


@app.route("/dashboard")
def dashboard() -> Response:
    user = session.get("user")
    if not user:
        return redirect("/")
    body = (
        f"<h1>Welcome, {user}</h1>"
        "<p>You are signed in. <a href='/logout'>Logout</a></p>"
        "<form method='get' action='/search'>"
        "  <input name='q' placeholder='search...'>"
        "  <button type='submit'>Search</button>"
        "</form>"
    )
    return render("Dashboard", body)


@app.route("/logout")
def logout() -> Response:
    session.clear()
    return redirect("/")


@app.route("/search")
def search() -> Response:
    if not session.get("user"):
        return redirect("/")
    q = request.args.get("q", "")

    # Length guard: short on purpose so classic payloads are "too long".
    if len(q) > SEARCH_MAXLEN:
        body = (
            f"<h1>Search</h1><p class='warn'>Search query too long "
            f"(max {SEARCH_MAXLEN} characters). You sent {len(q)}.</p>"
            "<p><a href='/dashboard'>back</a></p>"
        )
        return render("Too long", body, status=400)

    # VULNERABLE ON PURPOSE: q is echoed without escaping -> reflected XSS.
    body = f"<h1>Search</h1><p>Results for: {q}</p><p><a href='/dashboard'>back</a></p>"
    return render("Search", body)


def main() -> None:
    _init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    if host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("ALLOW_PUBLIC") != "1":
        raise SystemExit(
            f"Refusing to bind to {host}: this app is intentionally vulnerable.\n"
            f"Set ALLOW_PUBLIC=1 only if you fully understand the risk (you shouldn't)."
        )
    print("=" * 64)
    print(" INTENTIONALLY VULNERABLE DEMO TARGET  —  authorized self-testing")
    print(f"   login:  http://{host}:{port}/      (admin / s3cr3t)")
    print(f"   search: http://{host}:{port}/search?q=...  (reflected XSS)")
    print("=" * 64)
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
