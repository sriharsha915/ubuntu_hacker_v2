"""Core package for the Iterative Attack Loop.

Modules
-------
models      : dataclasses + enums shared across the system
console     : the tagged, human-readable terminal renderer ([ACTION], [ATTACK], ...)
scope       : authorization / scope guard (keeps testing to authorized targets)
executor    : the Feedback Phase -> run shell commands, capture stdout/stderr
browser     : the Action Phase -> headed browser driver (Playwright) + HTTP probe
payloads    : XSS / SQLi payload libraries with metadata
strategist  : the Rectification Phase -> the "brain" that decides the next move
loop        : the AttackLoop state machine that ties everything together
report      : engagement report writer (JSON + Markdown)
"""

from __future__ import annotations

__all__ = [
    "models",
    "console",
    "scope",
    "executor",
    "browser",
    "payloads",
    "strategist",
    "loop",
    "report",
]

__version__ = "1.0.0"
