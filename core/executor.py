"""The Feedback Phase: run shell commands on Ubuntu and capture everything.

This is what turns a raw `stdout`/`stderr`/exit-code into the Observation the
brain reasons over. It also carries a safety denylist so the loop can't be
talked into wiping a disk by a confused (or adversarial) planner.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time
from typing import Dict, List, Optional

from .models import Observation


# Patterns that are almost never what a scoped web-app test wants to run.
# These are refused unless the operator passes allow_dangerous=True.
_DANGEROUS = [
    re.compile(r"\brm\s+-[rf]{1,2}\b.*\s/(?:\s|$)"),      # rm -rf /
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\b.*\bof=/dev/"),
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"),
    re.compile(r">\s*/dev/sd[a-z]"),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),             # fork bomb
    re.compile(r"\bchmod\s+-R\s+0*7{3}\s+/"),
    re.compile(r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(bash|sh)\b"),  # curl | bash
]

_MAX_CAPTURE = 20_000  # chars kept per stream before truncation


class ExecutionBlocked(Exception):
    pass


def _truncate(text: str) -> str:
    if len(text) <= _MAX_CAPTURE:
        return text
    head = text[: _MAX_CAPTURE]
    return head + f"\n... [truncated {len(text) - _MAX_CAPTURE} chars] ..."


class CommandExecutor:
    def __init__(
        self,
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        allow_dangerous: bool = False,
    ):
        self.timeout = timeout
        self.cwd = cwd
        self.env = env
        self.allow_dangerous = allow_dangerous

    def _guard(self, command: str) -> None:
        if self.allow_dangerous:
            return
        for pat in _DANGEROUS:
            if pat.search(command):
                raise ExecutionBlocked(
                    f"Refused to run a command matching a destructive pattern "
                    f"({pat.pattern!r}). Re-run with --allow-dangerous if this is "
                    f"truly intended."
                )

    def run(
        self,
        command: str,
        shell: bool = True,
        timeout: Optional[float] = None,
    ) -> Observation:
        """Run a command, capture stdout/stderr, and classify the result."""
        self._guard(command)
        t0 = time.time()
        try:
            proc = subprocess.run(
                command if shell else shlex.split(command),
                shell=shell,
                cwd=self.cwd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
            )
            dur = time.time() - t0
            stdout = _truncate(proc.stdout or "")
            stderr = _truncate(proc.stderr or "")
            ok = proc.returncode == 0
            error = ""
            if not ok:
                last = (stderr.strip().splitlines() or [""])[-1]
                error = last or f"exit code {proc.returncode}"
            return Observation(
                ok=ok,
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                error=error,
                duration_s=dur,
            )
        except subprocess.TimeoutExpired as exc:
            return Observation(
                ok=False,
                returncode=None,
                stdout=_truncate(exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")),
                stderr=_truncate(exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")),
                error=f"timed out after {timeout or self.timeout:.0f}s",
                duration_s=time.time() - t0,
            )
        except FileNotFoundError as exc:
            return Observation(ok=False, error=f"command not found: {exc}", duration_s=time.time() - t0)
        except Exception as exc:  # pragma: no cover - defensive
            return Observation(ok=False, error=f"{type(exc).__name__}: {exc}", duration_s=time.time() - t0)
