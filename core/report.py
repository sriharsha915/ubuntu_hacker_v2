"""Engagement report writer.

Every run drops a timestamped folder under engagements/ with:
    report.json  - the full machine-readable state (every step + observation)
    report.md    - a human-readable summary you can paste into a ticket

Nothing here is required for the loop to work; it's the audit trail.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

from .models import EngagementState, Verdict


def _ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime())


def _fmt_time(epoch: Optional[float]) -> str:
    if not epoch:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


class ReportWriter:
    def __init__(self, base_dir: str = "engagements"):
        self.base_dir = base_dir

    def write(self, state: EngagementState) -> str:
        folder = os.path.join(self.base_dir, f"{_ts()}-{state.objective.kind}")
        os.makedirs(folder, exist_ok=True)

        json_path = os.path.join(folder, "report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(self._as_json(state), fh, indent=2, default=str)

        md_path = os.path.join(folder, "report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(self._as_markdown(state))

        return folder

    # ----------------------------------------------------------------------
    def _as_json(self, state: EngagementState) -> dict:
        return {
            "objective": {
                "name": state.objective.name,
                "kind": state.objective.kind,
                "target_url": state.objective.target_url,
                "component": state.objective.component,
                "success_criteria": state.objective.success_criteria,
            },
            "verdict": state.verdict.value,
            "iterations": state.iterations,
            "started_at": _fmt_time(state.started_at),
            "finished_at": _fmt_time(state.finished_at),
            "findings": [vars(f) for f in state.findings],
            "steps": [self._step_json(s) for s in state.steps],
        }

    def _step_json(self, s) -> dict:
        obs = s.observation
        return {
            "index": s.index,
            "action": s.action_kind,
            "payload": (s.payload.value if s.payload else None),
            "payload_name": (s.payload.name if s.payload else None),
            "ok": (obs.ok if obs else None),
            "signal": (obs.signal if obs else None),
            "error": (obs.error if obs else None),
            "detail": (obs.signal_detail if obs else None),
            "evidence": (obs.evidence if obs else None),
            "decision": s.decision,
            "rationale": s.rationale,
        }

    # ----------------------------------------------------------------------
    def _as_markdown(self, state: EngagementState) -> str:
        o = state.objective
        verdict_badge = {
            Verdict.VULNERABLE: "🔴 VULNERABLE",
            Verdict.SAFE: "🟢 SAFE",
            Verdict.INCONCLUSIVE: "🟡 INCONCLUSIVE",
            Verdict.ABORTED: "⚪ ABORTED",
            Verdict.PENDING: "PENDING",
        }[state.verdict]

        lines = [
            f"# Attack Loop Report — {o.name}",
            "",
            f"- **Verdict:** {verdict_badge}",
            f"- **Technique:** `{o.kind}`",
            f"- **Target:** {o.target_url}",
            f"- **Component:** {o.component}",
            f"- **Success criteria:** {o.success_criteria}",
            f"- **Iterations:** {state.iterations}",
            f"- **Started:** {_fmt_time(state.started_at)}",
            f"- **Finished:** {_fmt_time(state.finished_at)}",
            "",
        ]

        if state.findings:
            lines.append("## Findings")
            lines.append("")
            for f in state.findings:
                lines.append(f"### {f.title}  ({f.severity.upper()})")
                lines.append("")
                lines.append(f"- **Payload:** `{f.payload}`")
                lines.append(f"- **Evidence:** {f.evidence}")
                lines.append("- **Reproduction:**")
                for step in f.reproduction:
                    lines.append(f"  - {step}")
                lines.append("")

        lines.append("## Transcript")
        lines.append("")
        lines.append("| # | Payload | ok | signal | error / detail | decision |")
        lines.append("|---|---------|----|--------|----------------|----------|")
        for s in state.steps:
            obs = s.observation
            payload = (s.payload.short(40) if s.payload else "-")
            ok = "✓" if (obs and obs.ok) else "✗"
            sig = "🚨" if (obs and obs.signal) else ""
            detail = ""
            if obs:
                detail = obs.signal_detail or obs.error or ""
            payload = payload.replace("|", "\\|")
            detail = detail.replace("|", "\\|")[:60]
            lines.append(f"| {s.index} | `{payload}` | {ok} | {sig} | {detail} | {s.decision or ''} |")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("_Generated by the Iterative Attack Loop. Authorized testing only._")
        return "\n".join(lines)
