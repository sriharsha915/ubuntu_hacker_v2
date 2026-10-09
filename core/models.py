"""Shared data models and enums for the Iterative Attack Loop.

Everything here is intentionally dependency-free (stdlib only) so that every
other module can import it without pulling in optional packages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class EventTag(str, Enum):
    """The tags rendered in the terminal so progress reads as a sequence."""

    ACTION = "ACTION"    # opening a browser, navigating, running a command
    INPUT = "INPUT"      # entering credentials / filling a field
    ATTACK = "ATTACK"    # crafting / firing a payload
    OBSERVE = "OBSERVE"  # what came back
    ERROR = "ERROR"      # the attempt failed (target rejected it, tool error)
    SIGNAL = "SIGNAL"    # a possible vulnerability signal was detected
    RECTIFY = "RECTIFY"  # the brain adjusting the path
    VERDICT = "VERDICT"  # final conclusion
    INFO = "INFO"        # scaffolding / context
    PLAN = "PLAN"        # the brain announcing its intent


class ActionKind(str, Enum):
    OPEN_BROWSER = "open_browser"
    NAVIGATE = "navigate"
    LOGIN = "login"
    FILL = "fill"
    SUBMIT = "submit"
    FIRE_PAYLOAD = "fire_payload"
    RUN_COMMAND = "run_command"
    CHECK_SIGNAL = "check_signal"
    CONCLUDE = "conclude"


class Decision(str, Enum):
    """What the brain decides to do after observing a result."""

    RE_ATTACK = "re_attack"            # same path, tweak and try again
    MUTATE = "mutate"                  # change the payload (encode / shorten)
    NEW_PATH = "new_path"              # switch technique / vector
    ESCALATE = "escalate"              # a signal appeared; try to confirm it
    CONCLUDE_VULNERABLE = "vulnerable" # we have evidence
    CONCLUDE_SAFE = "safe"             # everything was tried and survived
    ABORT = "abort"                    # stop (scope / error / user)


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ABORTED = "ABORTED"
    PENDING = "PENDING"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------
@dataclass
class Payload:
    """A single candidate attack vector."""

    value: str
    name: str = ""
    technique: str = ""                 # e.g. "reflected-xss", "sqli-auth-bypass"
    context: str = "html"               # where it is meant to land: html/attr/js/url
    note: str = ""
    encoded: bool = False

    @property
    def length(self) -> int:
        return len(self.value)

    def short(self, width: int = 48) -> str:
        v = self.value.replace("\n", "\\n")
        return v if len(v) <= width else v[: width - 1] + "…"


@dataclass
class Observation:
    """The result of performing one action. This is the 'Feedback Phase' payload."""

    ok: bool = True                     # did the action complete without a tool/target error?
    signal: bool = False                # did we detect a vulnerability signal?
    signal_detail: str = ""             # human description of the signal / evidence
    returncode: Optional[int] = None    # for shell commands
    stdout: str = ""
    stderr: str = ""
    error: str = ""                     # short classification of why ok is False
    evidence: Dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    def summary(self) -> str:
        if self.signal:
            return self.signal_detail or "signal detected"
        if not self.ok:
            return self.error or (self.stderr.strip().splitlines()[-1] if self.stderr.strip() else "failed")
        return "no signal (survived)"


@dataclass
class Move:
    """What the strategist proposes to do next."""

    kind: str                           # "attack" | "conclude_safe" | "conclude_vulnerable" | "abort"
    rationale: str = ""
    payload: Optional[Payload] = None
    decision: Decision = Decision.RE_ATTACK


@dataclass
class Rectification:
    """How the strategist adjusts after an (failed or survived) attempt."""

    decision: Decision
    narration: str


@dataclass
class Step:
    index: int
    action_kind: str
    description: str
    payload: Optional[Payload] = None
    observation: Optional[Observation] = None
    decision: Optional[str] = None
    rationale: str = ""
    at: float = field(default_factory=time.time)


@dataclass
class Finding:
    title: str
    severity: str
    technique: str
    target: str
    payload: str
    evidence: str
    reproduction: List[str] = field(default_factory=list)


@dataclass
class Objective:
    """What a single run is trying to prove about one component."""

    name: str
    kind: str                           # "reflected-xss" | "sqli-login" | ...
    target_url: str
    component: str = ""                 # human label, e.g. "search field"
    params: Dict[str, Any] = field(default_factory=dict)
    success_criteria: str = ""


@dataclass
class EngagementState:
    """The full, serialisable state of one attack loop."""

    objective: Objective
    steps: List[Step] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    verdict: Verdict = Verdict.PENDING
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    # convenience -----------------------------------------------------------
    @property
    def iterations(self) -> int:
        return sum(1 for s in self.steps if s.payload is not None)

    @property
    def last_observation(self) -> Optional[Observation]:
        for s in reversed(self.steps):
            if s.observation is not None:
                return s.observation
        return None

    def attempted_payloads(self) -> List[str]:
        return [s.payload.value for s in self.steps if s.payload is not None]

    def record(self, step: Step) -> None:
        self.steps.append(step)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # enums -> their string value for clean JSON
        d["verdict"] = self.verdict.value
        return d
