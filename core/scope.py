"""Authorization / scope guard.

This is a dual-use tool: the same loop that tests *your* app could be pointed
at someone else's. The ScopeGuard makes "only authorized targets" the default
behaviour instead of a thing you have to remember.

Rules
-----
* localhost targets (127.0.0.1, ::1, *.localhost, *.test) are always allowed.
* Any other host must be explicitly authorized, either by:
    - passing it on the --authorize-host list, or
    - the global --i-have-authorization flag, or
    - typing the host back at an interactive prompt.
* The grant and a timestamp are written to the engagement log for accountability.
"""

from __future__ import annotations

import sys
from typing import List, Optional
from urllib.parse import urlparse


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
LOCAL_SUFFIXES = (".localhost", ".test", ".local")


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""


def host_of(url: str) -> str:
    parsed = urlparse(url if "//" in url else "//" + url)
    return (parsed.hostname or "").lower()


def is_local(url: str) -> bool:
    h = host_of(url)
    if h in LOCAL_HOSTS:
        return True
    return any(h.endswith(s) for s in LOCAL_SUFFIXES)


class ScopeGuard:
    def __init__(
        self,
        authorized_hosts: Optional[List[str]] = None,
        blanket_authorization: bool = False,
        assume_yes: bool = False,
        interactive: bool = True,
    ):
        self.authorized_hosts = {h.lower() for h in (authorized_hosts or [])}
        self.blanket_authorization = blanket_authorization
        self.assume_yes = assume_yes
        self.interactive = interactive
        self.grants: List[str] = []

    def authorize(self, url: str) -> None:
        host = host_of(url)
        if not host:
            raise ScopeError(f"Could not parse a host from target URL: {url!r}")

        if is_local(url):
            self.grants.append(f"{host} (localhost, auto-authorized)")
            return

        if host in self.authorized_hosts:
            self.grants.append(f"{host} (on --authorize-host list)")
            return

        if self.blanket_authorization:
            self.grants.append(f"{host} (--i-have-authorization)")
            return

        if self.assume_yes or not self.interactive:
            raise ScopeError(
                f"Target host '{host}' is not localhost and was not authorized.\n"
                f"Re-run with --authorize-host {host} or --i-have-authorization\n"
                f"ONLY if you have written permission to test this system."
            )

        # interactive confirmation -----------------------------------------
        sys.stderr.write(
            "\n"
            "  !!  You are about to attack a NON-LOCAL target:\n"
            f"        {url}\n"
            "      Only proceed if you have explicit written authorization\n"
            "      (an engagement letter / scope document) to test it.\n"
            f"      Type the hostname to confirm authorization [{host}]: "
        )
        sys.stderr.flush()
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != host:
            raise ScopeError(f"Authorization not confirmed for '{host}'. Aborting.")
        self.authorized_hosts.add(host)
        self.grants.append(f"{host} (interactively confirmed)")
