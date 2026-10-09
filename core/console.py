"""The headed terminal experience.

The whole point of this module is that the loop should *read like a story*:

    [ACTION]  Opening browser at http://127.0.0.1:5000/search
    [INPUT]   Entering credentials for 'admin'
    [ATTACK]  Firing payload #3: <img src=x onerror=alert(1)>
    [ERROR]   Target rejected it: "Search query too long (max 40)"
    [RECTIFY] Shortening the vector -> switching to <svg onload=alert(1)>
    [SIGNAL]  alert() dialog fired -> reflected XSS confirmed
    [VERDICT] VULNERABLE

It uses `rich` when available for colour + panels, and falls back to plain
ANSI so it still works on a bare Ubuntu box with nothing installed.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Optional

from .models import EventTag, EngagementState, Observation, Step, Verdict

try:  # optional pretty renderer
    from rich.console import Console as _RichConsole
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.text import Text
    _HAS_RICH = True
except Exception:  # pragma: no cover - fallback path
    _HAS_RICH = False


# tag -> (ansi colour, rich style, glyph)
_TAG_STYLE = {
    EventTag.ACTION:  ("36", "bold cyan", "->"),
    EventTag.INPUT:   ("34", "bold blue", "<>"),
    EventTag.ATTACK:  ("35", "bold magenta", ">>"),
    EventTag.OBSERVE: ("37", "white", ".."),
    EventTag.ERROR:   ("31", "bold red", "!!"),
    EventTag.SIGNAL:  ("33", "bold yellow", "**"),
    EventTag.RECTIFY: ("33", "bold yellow", "~>"),
    EventTag.VERDICT: ("32", "bold green", "=="),
    EventTag.INFO:    ("90", "grey62", "--"),
    EventTag.PLAN:    ("36", "cyan", "::"),
}

_RESET = "\033[0m"


def _supports_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("ATTACK_LOOP_NO_COLOR"):
        return False
    return sys.stdout.isatty()


class Console:
    """Renders the tagged event stream and the transcript."""

    def __init__(self, use_rich: Optional[bool] = None, colour: Optional[bool] = None):
        self.colour = _supports_colour() if colour is None else colour
        self.use_rich = (_HAS_RICH and self.colour) if use_rich is None else use_rich
        self._rich = _RichConsole() if (self.use_rich and _HAS_RICH) else None
        self._t0 = time.time()

    # -- primitives ---------------------------------------------------------
    def _elapsed(self) -> str:
        return f"{time.time() - self._t0:6.2f}s"

    def event(self, tag: EventTag, message: str) -> None:
        colour, style, glyph = _TAG_STYLE[tag]
        ts = self._elapsed()
        label = f"[{tag.value}]"
        if self._rich is not None:
            text = Text()
            text.append(f"{ts} ", style="grey42")
            text.append(f"{label:<9}", style=style)
            text.append(message)
            self._rich.print(text)
        elif self.colour:
            sys.stdout.write(
                f"\033[90m{ts}\033[0m "
                f"\033[{colour}m{label:<9}\033[0m {message}\n"
            )
            sys.stdout.flush()
        else:
            sys.stdout.write(f"{ts} {label:<9} {message}\n")
            sys.stdout.flush()

    # -- tag shortcuts ------------------------------------------------------
    def action(self, m: str) -> None:  self.event(EventTag.ACTION, m)
    def input_(self, m: str) -> None:  self.event(EventTag.INPUT, m)
    def attack(self, m: str) -> None:  self.event(EventTag.ATTACK, m)
    def observe(self, m: str) -> None: self.event(EventTag.OBSERVE, m)
    def error(self, m: str) -> None:   self.event(EventTag.ERROR, m)
    def signal(self, m: str) -> None:  self.event(EventTag.SIGNAL, m)
    def rectify(self, m: str) -> None: self.event(EventTag.RECTIFY, m)
    def info(self, m: str) -> None:    self.event(EventTag.INFO, m)
    def plan(self, m: str) -> None:    self.event(EventTag.PLAN, m)

    # -- larger blocks ------------------------------------------------------
    def rule(self, title: str = "") -> None:
        if self._rich is not None:
            self._rich.print(Rule(title))
        else:
            line = "-" * 72
            if title:
                line = f"--- {title} " + "-" * max(0, 68 - len(title))
            self._plain(line, "90")

    def banner(self, title: str, subtitle: str = "") -> None:
        body = title if not subtitle else f"{title}\n{subtitle}"
        if self._rich is not None:
            self._rich.print(Panel.fit(body, border_style="bold magenta"))
        else:
            width = max(len(l) for l in body.splitlines())
            bar = "=" * (width + 4)
            self._plain(bar, "35")
            for l in body.splitlines():
                self._plain(f"= {l.ljust(width)} =", "35")
            self._plain(bar, "35")

    def verdict(self, state: EngagementState) -> None:
        v = state.verdict
        colour = {
            Verdict.VULNERABLE: ("31", "bold white on red"),
            Verdict.SAFE: ("32", "bold white on green"),
            Verdict.INCONCLUSIVE: ("33", "bold black on yellow"),
            Verdict.ABORTED: ("90", "bold white on grey30"),
            Verdict.PENDING: ("90", "grey62"),
        }[v]
        headline = f" VERDICT: {v.value} "
        detail = self._verdict_detail(state)
        if self._rich is not None:
            self._rich.print(Panel(detail, title=headline, border_style=colour[1].split()[-1]))
        else:
            self.event(EventTag.VERDICT, v.value)
            for line in detail.splitlines():
                self._plain("           " + line, colour[0])

    def _verdict_detail(self, state: EngagementState) -> str:
        lines = [
            f"component : {state.objective.component or state.objective.name}",
            f"technique : {state.objective.kind}",
            f"target    : {state.objective.target_url}",
            f"iterations: {state.iterations}",
        ]
        if state.findings:
            f = state.findings[0]
            lines.append(f"evidence  : {f.evidence}")
            lines.append(f"payload   : {f.payload}")
        return "\n".join(lines)

    # -- helpers ------------------------------------------------------------
    def _plain(self, text: str, colour: str) -> None:
        if self.colour:
            sys.stdout.write(f"\033[{colour}m{text}\033[0m\n")
        else:
            sys.stdout.write(text + "\n")
        sys.stdout.flush()

    def blank(self) -> None:
        sys.stdout.write("\n")

    def dump_feedback_block(self, state: EngagementState, obs: Observation) -> str:
        """Render an LLM-ready block the user can paste into a chat window.

        This is the bridge for the *manual* loop: copy this, drop it into your
        LLM, and paste the suggested next payload back in.
        """
        obj = state.objective
        tried = "\n".join(f"  - {p}" for p in state.attempted_payloads()) or "  (none yet)"
        block = f"""================= FEED THIS BACK TO THE LLM =================
OBJECTIVE : {obj.name} ({obj.kind})
TARGET    : {obj.target_url}
COMPONENT : {obj.component}
SUCCESS   : {obj.success_criteria}

LAST ATTEMPT
  ok        : {obs.ok}
  signal    : {obs.signal}
  error     : {obs.error or '-'}
  returncode: {obs.returncode}
  stdout    : {obs.stdout.strip()[:800] or '-'}
  stderr    : {obs.stderr.strip()[:800] or '-'}
  detail    : {obs.signal_detail or '-'}

PAYLOADS ALREADY TRIED
{tried}

ASK
  Given the objective and the last result, what is the single best next
  payload to try? Reply with ONLY the raw payload on one line, or the word
  SAFE if the component should be declared safe, or VULN if the last result
  already proves the vulnerability.
============================================================"""
        if self._rich is not None:
            self._rich.print(Panel(block, border_style="cyan"))
        else:
            self._plain(block, "36")
        return block
