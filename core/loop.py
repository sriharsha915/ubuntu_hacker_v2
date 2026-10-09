"""The AttackLoop state machine.

    authorize -> open -> preflight -> [ propose -> act -> observe -> rectify ]* -> verdict

This is the only place that knows the full choreography. Brain (strategist),
hands (scenario), eyes (driver), and voice (console) are all injected, so the
loop itself stays small and testable.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from .browser import DriverError
from .models import (
    Decision,
    EngagementState,
    Finding,
    Observation,
    Severity,
    Step,
    Verdict,
)
from .scope import ScopeError, ScopeGuard
from .strategist import StrategistError


_SEVERITY_BY_KIND = {
    "sqli-login": Severity.CRITICAL,
    "sqli": Severity.CRITICAL,
    "reflected-xss": Severity.HIGH,
    "xss": Severity.HIGH,
}


class AttackLoop:
    def __init__(
        self,
        scenario,
        driver,
        strategist,
        console,
        scope: Optional[ScopeGuard] = None,
        max_iterations: int = 12,
        screenshot_dir: Optional[str] = None,
    ):
        self.scenario = scenario
        self.driver = driver
        self.strategist = strategist
        self.console = console
        self.scope = scope or ScopeGuard()
        self.max_iterations = max_iterations
        self.screenshot_dir = screenshot_dir

    # ----------------------------------------------------------------------
    def run(self) -> EngagementState:
        state = EngagementState(objective=self.scenario.objective())
        c = self.console

        c.banner(
            "ITERATIVE ATTACK LOOP",
            f"{state.objective.name}\nbrain={self.strategist.name}  "
            f"driver={self.driver.kind}  max_iter={self.max_iterations}",
        )

        # -- scope gate -----------------------------------------------------
        try:
            self.scope.authorize(self.scenario.target_url)
            for grant in self.scope.grants:
                c.info(f"authorized: {grant}")
        except ScopeError as exc:
            c.error(str(exc))
            state.verdict = Verdict.ABORTED
            state.finished_at = time.time()
            c.verdict(state)
            return state

        # -- action phase: open the driver ---------------------------------
        c.action(f"Opening {self.driver.kind} driver "
                 f"({'headed browser' if self.driver.kind == 'browser' else 'no-browser probe'})...")
        try:
            self.driver.start()
        except DriverError as exc:
            c.error(str(exc))
            state.verdict = Verdict.ABORTED
            state.finished_at = time.time()
            c.verdict(state)
            return state

        try:
            c.action(f"Navigating to {self.scenario.target_url}")
            self.scenario.preflight(self.driver, c)
            c.rule("attack loop")
            self._drive(state)
        except StrategistError as exc:
            c.error(str(exc))
            state.verdict = Verdict.ABORTED
        except KeyboardInterrupt:
            c.error("Interrupted by operator.")
            if state.verdict == Verdict.PENDING:
                state.verdict = Verdict.ABORTED
        finally:
            try:
                self.driver.stop()
            except Exception:
                pass

        if state.verdict == Verdict.PENDING:
            # Ran out of iteration budget before a conclusion.
            state.verdict = Verdict.INCONCLUSIVE
            c.info(f"Reached the {self.max_iterations}-iteration budget without a conclusion.")

        state.finished_at = time.time()
        c.rule("verdict")
        c.verdict(state)
        return state

    # ----------------------------------------------------------------------
    def _drive(self, state: EngagementState) -> None:
        c = self.console
        for i in range(1, self.max_iterations + 1):
            move = self.strategist.propose(state, self.scenario, c)

            if move.kind != "attack":
                self._conclude_from_move(state, move)
                return

            c.plan(move.rationale)
            obs = self.scenario.attempt(self.driver, c, move.payload)

            step = Step(
                index=i,
                action_kind="fire_payload",
                description=f"fire {move.payload.name}",
                payload=move.payload,
                observation=obs,
                rationale=move.rationale,
            )
            state.record(step)

            if obs.signal:
                rect = self.strategist.rectify(state, obs, c)   # let the brain see it too
                step.decision = rect.decision.value
                self._conclude_vulnerable(state, move.payload, obs)
                return

            rect = self.strategist.rectify(state, obs, c)
            step.decision = rect.decision.value
            step.rationale = rect.narration
            c.rectify(rect.narration)

    # ----------------------------------------------------------------------
    def _conclude_from_move(self, state: EngagementState, move) -> None:
        if move.kind == "conclude_vulnerable" or move.decision == Decision.CONCLUDE_VULNERABLE:
            last = state.last_observation or Observation(ok=True, signal=True,
                                                         signal_detail=move.rationale)
            last_payload = None
            for s in reversed(state.steps):
                if s.payload is not None:
                    last_payload = s.payload
                    break
            self._conclude_vulnerable(state, last_payload, last, note=move.rationale)
        elif move.kind == "conclude_safe" or move.decision == Decision.CONCLUDE_SAFE:
            state.verdict = Verdict.SAFE
            self.console.info(move.rationale or "Component survived every attempted vector.")
        else:  # abort
            state.verdict = Verdict.ABORTED
            self.console.info(move.rationale or "Loop aborted.")

    def _conclude_vulnerable(self, state, payload, obs, note: str = "") -> None:
        kind = state.objective.kind
        sev = _SEVERITY_BY_KIND.get(kind, Severity.MEDIUM)
        shot = self._maybe_screenshot(state)
        repro = [
            f"Target: {state.objective.target_url}",
            f"Component: {state.objective.component}",
        ]
        if payload is not None:
            repro.append(f"Payload: {payload.value}")
        if obs and obs.signal_detail:
            repro.append(f"Observed: {obs.signal_detail}")
        if shot:
            repro.append(f"Screenshot: {shot}")

        finding = Finding(
            title=f"{kind} in {state.objective.component}",
            severity=sev.value,
            technique=kind,
            target=state.objective.target_url,
            payload=(payload.value if payload is not None else note),
            evidence=(obs.signal_detail if obs and obs.signal_detail else note) or "see transcript",
            reproduction=repro,
        )
        state.findings.append(finding)
        state.verdict = Verdict.VULNERABLE

    def _maybe_screenshot(self, state) -> Optional[str]:
        if not self.screenshot_dir:
            return None
        try:
            os.makedirs(self.screenshot_dir, exist_ok=True)
            path = os.path.join(
                self.screenshot_dir,
                f"{state.objective.kind}-{state.iterations}.png",
            )
            return self.driver.screenshot(path)
        except Exception:
            return None
