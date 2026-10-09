"""The Rectification Phase: the "brain" that drives the loop.

A Strategist answers two questions, over and over:

    propose(state) -> Move          "what should I try next?"
    rectify(state, observation)     "that result came back - how do I adjust?"

Four implementations ship:

* RuleBasedStrategist - a deterministic playbook. Zero dependencies, always
  runnable, and it reproduces the canonical story:
      [ATTACK] long payload -> [ERROR] too long -> [RECTIFY] shorten -> [SIGNAL]
* QwenStrategist       - the LLM GENERATES every payload at runtime via any
  OpenAI-compatible endpoint (Ollama / vLLM / LM Studio / DashScope). Nothing
  is hardcoded: you say "SQLi", Qwen returns the payloads, they flow into the
  form-field placeholders and get fired.
* ClaudeStrategist     - a real closed loop driven by the Anthropic API. The
  model is handed the transcript each turn and returns the next move via a
  forced tool call (structured output, no fragile text parsing).
* HumanStrategist      - YOU are the brain. It prints an LLM-ready block, you
  paste it into ChatGPT / Claude / whatever, and feed the suggestion back.

Every strategist returns the same Move/Rectification types, so the loop never
needs to know which brain it is talking to.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from .models import (
    Decision,
    Move,
    Observation,
    Payload,
    Rectification,
    EngagementState,
)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class StrategistError(RuntimeError):
    """Expected, actionable strategist setup problem (missing dep / API key)."""


class Strategist:
    name = "base"

    def propose(self, state: EngagementState, scenario, console) -> Move:
        raise NotImplementedError

    def rectify(self, state: EngagementState, obs: Observation, console) -> Rectification:
        """Default narration shared by subclasses that don't override it."""
        if obs.signal:
            return Rectification(Decision.ESCALATE, "Signal detected -> confirming and concluding.")
        if not obs.ok:
            return Rectification(Decision.MUTATE, f"Attempt failed ({obs.error}). Adjusting the vector.")
        return Rectification(Decision.NEW_PATH, "No signal (component survived). Trying the next vector.")

    # shared helper ---------------------------------------------------------
    @staticmethod
    def _length_cap_from_error(error: str) -> Optional[int]:
        """Pull a max length out of an error like 'too long (max 30 chars)'."""
        if not error:
            return None
        if not re.search(r"too long|max(?:imum)? length|length limit|exceeds", error, re.I):
            return None
        m = re.search(r"(\d{1,5})", error)
        return int(m.group(1)) if m else 0


# ---------------------------------------------------------------------------
# Rule-based playbook
# ---------------------------------------------------------------------------
class RuleBasedStrategist(Strategist):
    name = "rule"

    def __init__(self):
        self._queue: Optional[List[Payload]] = None

    def _ensure_queue(self, scenario) -> None:
        if self._queue is None:
            self._queue = list(scenario.candidate_payloads())

    def propose(self, state: EngagementState, scenario, console) -> Move:
        self._ensure_queue(scenario)

        last = state.last_observation
        if last is not None and last.signal:
            return Move(
                kind="conclude_vulnerable",
                rationale="A vulnerability signal was observed; concluding.",
                decision=Decision.CONCLUDE_VULNERABLE,
            )

        if not self._queue:
            return Move(
                kind="conclude_safe",
                rationale="Every vector in the playbook was tried and survived.",
                decision=Decision.CONCLUDE_SAFE,
            )

        payload = self._queue.pop(0)
        return Move(
            kind="attack",
            payload=payload,
            rationale=f"Trying {payload.name} ({payload.context}-context, {payload.length} chars).",
            decision=Decision.RE_ATTACK,
        )

    def rectify(self, state: EngagementState, obs: Observation, console) -> Rectification:
        self._ensure_queue(None) if self._queue is None else None

        if obs.signal:
            return Rectification(Decision.ESCALATE, "Signal observed -> escalating to a verdict.")

        # The headline rectification: payload rejected for being too long.
        cap = self._length_cap_from_error(obs.error)
        if cap is not None and self._queue:
            before = len(self._queue)
            self._queue = [p for p in self._queue if cap == 0 or p.length <= cap]
            dropped = before - len(self._queue)
            nxt = self._queue[0].short() if self._queue else "(no shorter vector left)"
            cap_txt = f"{cap} chars" if cap else "the field limit"
            return Rectification(
                Decision.MUTATE,
                f"Payload too long for field (limit {cap_txt}). "
                f"Dropping {dropped} oversized vector(s); shortening to {nxt}.",
            )

        if not obs.ok:
            return Rectification(
                Decision.MUTATE,
                f"Attempt failed ({obs.error}). Moving to the next vector.",
            )

        return Rectification(
            Decision.NEW_PATH,
            "No signal (component held). Switching to the next vector / context.",
        )


# ---------------------------------------------------------------------------
# Human-in-the-loop (the manual "paste into your LLM" mode)
# ---------------------------------------------------------------------------
class HumanStrategist(Strategist):
    name = "human"

    def propose(self, state: EngagementState, scenario, console) -> Move:
        last = state.last_observation or Observation(ok=True)
        console.dump_feedback_block(state, last)
        try:
            raw = input("  Paste next payload (or SAFE / VULN / quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            raw = "quit"

        low = raw.lower()
        if low in ("", "quit", "q", "stop"):
            return Move(kind="abort", rationale="Operator ended the loop.", decision=Decision.ABORT)
        if low in ("safe", "s"):
            return Move(kind="conclude_safe", rationale="Operator declared the component safe.",
                        decision=Decision.CONCLUDE_SAFE)
        if low in ("vuln", "vulnerable", "v"):
            return Move(kind="conclude_vulnerable", rationale="Operator declared a vulnerability.",
                        decision=Decision.CONCLUDE_VULNERABLE)
        return Move(
            kind="attack",
            payload=Payload(value=raw, name="operator-supplied", technique=scenario.kind,
                            context="html", note="Pasted from the operator's own LLM."),
            rationale="Operator / external-LLM supplied this vector.",
            decision=Decision.RE_ATTACK,
        )


# ---------------------------------------------------------------------------
# Claude-driven closed loop
# ---------------------------------------------------------------------------
_CLAUDE_SYSTEM = """You are the planning brain of an AUTHORIZED, scoped web-application
security test. A harness performs the actions you choose against a target the
operator is authorized to test, captures the result, and feeds it back to you.

Your job each turn: look at the objective and the transcript so far and choose
the single best next move. Prefer concrete, minimal payloads. When a payload is
rejected for length, shorten it. When a vector is clearly neutralised, switch
technique or context. Conclude VULNERABLE only when the evidence supports it
(e.g. an alert() dialog fired, an authentication bypass succeeded, or a SQL
error proves injection). Conclude SAFE once reasonable vectors are exhausted.

You MUST respond by calling the choose_next_move tool. Never free-type."""

_MOVE_TOOL = {
    "name": "choose_next_move",
    "description": "Choose the next action in the iterative attack loop.",
    "input_schema": {
        "type": "object",
        "properties": {
            "move": {
                "type": "string",
                "enum": ["attack", "conclude_vulnerable", "conclude_safe", "abort"],
                "description": "attack = fire the payload; conclude_* = end the loop with a verdict.",
            },
            "payload": {
                "type": "string",
                "description": "The raw payload to fire (required when move=attack).",
            },
            "rationale": {
                "type": "string",
                "description": "One sentence: why this move, given the last result.",
            },
        },
        "required": ["move", "rationale"],
    },
}

DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8")


class ClaudeStrategist(Strategist):
    name = "claude"

    def __init__(self, model: Optional[str] = None, max_tokens: int = 500):
        self.model = model or DEFAULT_MODEL
        self.max_tokens = max_tokens
        self._client = None
        self._messages: List[dict] = []
        self._last_rationale = ""
        self._primed = False

    def _ensure_client(self):
        if self._client is not None:
            return
        try:
            from anthropic import Anthropic
        except Exception as exc:  # pragma: no cover
            raise StrategistError(
                "The 'anthropic' package is required for --strategist claude. "
                "Install it (pip install anthropic) or use --strategist rule/human."
            ) from exc
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise StrategistError(
                "ANTHROPIC_API_KEY is not set. Export it, or use "
                "--strategist rule (no key needed) / --strategist human."
            )
        self._client = Anthropic()

    def _prime(self, state: EngagementState, scenario) -> None:
        if self._primed:
            return
        obj = state.objective
        hints = "\n".join(
            f"  - {p.name}: {p.short(60)}" for p in scenario.candidate_payloads()[:8]
        )
        self._messages.append({
            "role": "user",
            "content": (
                f"OBJECTIVE: {obj.name} ({obj.kind})\n"
                f"TARGET:    {obj.target_url}\n"
                f"COMPONENT: {obj.component}\n"
                f"SUCCESS:   {obj.success_criteria}\n\n"
                f"The harness detects a vulnerability when: {scenario.signal_description()}\n\n"
                f"Reference vectors you may use or adapt:\n{hints}\n\n"
                f"Choose the first move."
            ),
        })
        self._primed = True

    def propose(self, state: EngagementState, scenario, console) -> Move:
        self._ensure_client()
        self._prime(state, scenario)

        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=_CLAUDE_SYSTEM,
                tools=[_MOVE_TOOL],
                tool_choice={"type": "tool", "name": "choose_next_move"},
                messages=self._messages,
            )
        except Exception as exc:  # network / auth / bad model id / rate limit
            raise StrategistError(
                f"Anthropic API call failed ({type(exc).__name__}: {exc}). "
                f"Check ANTHROPIC_API_KEY and the model id "
                f"(ANTHROPIC_MODEL={self.model!r}), or use --strategist rule."
            ) from exc

        # record the assistant turn so the model keeps its own memory
        self._messages.append({"role": "assistant", "content": resp.content})

        tool_use = next((b for b in resp.content if getattr(b, "type", None) == "tool_use"), None)
        if tool_use is None:  # pragma: no cover - tool_choice should prevent this
            return Move(kind="abort", rationale="Model did not return a move.", decision=Decision.ABORT)

        args = tool_use.input or {}
        self._pending_tool_id = tool_use.id
        move = (args.get("move") or "abort").lower()
        rationale = args.get("rationale") or ""
        self._last_rationale = rationale

        if move == "attack":
            raw = args.get("payload") or ""
            if not raw:
                return Move(kind="conclude_safe", rationale="Model chose attack but gave no payload.",
                            decision=Decision.CONCLUDE_SAFE)
            return Move(
                kind="attack",
                payload=Payload(value=raw, name="claude", technique=scenario.kind,
                                context="html", note=rationale),
                rationale=rationale,
                decision=Decision.RE_ATTACK,
            )
        if move == "conclude_vulnerable":
            return Move(kind="conclude_vulnerable", rationale=rationale, decision=Decision.CONCLUDE_VULNERABLE)
        if move == "conclude_safe":
            return Move(kind="conclude_safe", rationale=rationale, decision=Decision.CONCLUDE_SAFE)
        return Move(kind="abort", rationale=rationale or "Model aborted.", decision=Decision.ABORT)

    def rectify(self, state: EngagementState, obs: Observation, console) -> Rectification:
        # Feed the result back to the model as a tool_result so the *next*
        # propose() sees exactly what happened.
        tool_id = getattr(self, "_pending_tool_id", None)
        feedback = (
            f"RESULT: ok={obs.ok} signal={obs.signal} "
            f"error={obs.error or '-'} detail={obs.signal_detail or '-'} "
            f"status={obs.evidence.get('status', '-')} "
            f"reflected={obs.evidence.get('reflected', '-')}"
        )
        if tool_id:
            self._messages.append({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": feedback}],
            })
            self._pending_tool_id = None
        else:
            self._messages.append({"role": "user", "content": feedback})

        if obs.signal:
            return Rectification(Decision.ESCALATE, self._last_rationale or "Signal observed; concluding.")
        if not obs.ok:
            return Rectification(Decision.MUTATE, f"Model will adjust after: {obs.error}")
        return Rectification(Decision.NEW_PATH, "Survived; model will pick a new vector.")


# ---------------------------------------------------------------------------
# Qwen (and any OpenAI-compatible endpoint: Ollama / vLLM / LM Studio / DashScope)
# ---------------------------------------------------------------------------
_QWEN_SYSTEM = """You are the planning brain of an AUTHORIZED, scoped web-application
security test. A harness performs the actions you choose against a target the
operator is authorized to test, captures the result, and feeds it back to you.

Each turn you choose the single best next move and GENERATE the exact payload
yourself (do not ask the harness for a payload — you produce it). Prefer concrete,
minimal payloads. When a payload is rejected for length, shorten it. When a vector
is clearly neutralised, switch technique or context. Conclude "vulnerable" only when
the evidence supports it (an alert() dialog fired, an auth bypass succeeded, or a
SQL error proves injection). Conclude "safe" once reasonable vectors are exhausted.

Respond with a SINGLE JSON object and NOTHING else, in exactly this shape:
  {"move": "attack" | "conclude_vulnerable" | "conclude_safe" | "abort",
   "payload": "<the raw payload string to fire; required when move is attack>",
   "rationale": "<one short sentence: why this move, given the last result>"}
Do not wrap it in markdown. Do not add commentary before or after the JSON."""


def _extract_json_object(text: str) -> Optional[dict]:
    """Pull the first balanced {...} JSON object out of a model response."""
    import json

    if not text:
        return None
    # strip code fences if the model added them
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass
    # fall back to the first balanced object
    start = cleaned.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start:i + 1])
                    except Exception:
                        break
        start = cleaned.find("{", start + 1)
    return None


class QwenStrategist(Strategist):
    """Drives the loop with Qwen (or any OpenAI-compatible chat endpoint).

    Every payload is GENERATED BY THE MODEL at runtime — nothing is hardcoded.
    Defaults target a local Ollama server; override via env or CLI:
        QWEN_BASE_URL (default http://localhost:11434/v1)
        QWEN_MODEL    (default qwen2.5-coder:7b)
        QWEN_API_KEY  (default 'ollama'; real key for DashScope/OpenRouter)
    """

    name = "qwen"

    def __init__(self, model=None, base_url=None, api_key=None,
                 max_tokens: int = 512, use_hints: bool = True, temperature: float = 0.4):
        self.base_url = (base_url or os.environ.get("QWEN_BASE_URL")
                         or "http://localhost:11434/v1").rstrip("/")
        self.model = model or os.environ.get("QWEN_MODEL") or "qwen2.5-coder:7b"
        self.api_key = api_key or os.environ.get("QWEN_API_KEY") or "ollama"
        self.max_tokens = max_tokens
        self.use_hints = use_hints
        self.temperature = temperature
        self._messages: List[dict] = []
        self._primed = False
        self._last_rationale = ""

    # -- HTTP boundary (overridden in tests) -------------------------------
    def _post(self, body: dict) -> dict:
        try:
            import requests
        except Exception as exc:  # pragma: no cover
            raise StrategistError(
                "The 'requests' package is required for --strategist qwen. "
                "Run scripts/install.sh, or use --strategist rule."
            ) from exc
        url = f"{self.base_url}/chat/completions"
        try:
            r = requests.post(
                url, json=body,
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                timeout=180,
            )
        except Exception as exc:
            raise StrategistError(
                f"Could not reach the Qwen endpoint at {url} ({type(exc).__name__}: {exc}). "
                f"Is the server running (e.g. 'ollama serve')? Set QWEN_BASE_URL / "
                f"QWEN_MODEL, or use --strategist rule."
            ) from exc
        if r.status_code >= 400:
            raise StrategistError(
                f"Qwen endpoint returned HTTP {r.status_code}: {r.text[:300]}. "
                f"Is the model pulled? Try: ollama pull {self.model}"
            )
        try:
            return r.json()
        except Exception as exc:
            raise StrategistError(f"Qwen endpoint returned non-JSON: {r.text[:200]}") from exc

    def _prime(self, state: EngagementState, scenario) -> None:
        if self._primed:
            return
        obj = state.objective
        hint_block = ""
        if self.use_hints:
            hints = "; ".join(p.short(40) for p in scenario.candidate_payloads()[:5])
            hint_block = (
                f"\nStyle references only (generate your own, do not just copy): {hints}"
            )
        self._messages.append({
            "role": "user",
            "content": (
                f"OBJECTIVE: {obj.name} ({obj.kind})\n"
                f"TARGET:    {obj.target_url}\n"
                f"COMPONENT: {obj.component}\n"
                f"SUCCESS:   {obj.success_criteria}\n"
                f"The harness detects a vulnerability when: {scenario.signal_description()}."
                f"{hint_block}\n\n"
                f"Produce the first move as JSON."
            ),
        })
        self._primed = True

    def propose(self, state: EngagementState, scenario, console) -> Move:
        self._prime(state, scenario)
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": _QWEN_SYSTEM}] + self._messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": False,
            "response_format": {"type": "json_object"},  # honoured by Ollama/vLLM; ignored elsewhere
        }
        data = self._post(body)
        try:
            content = data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise StrategistError(f"Unexpected Qwen response shape: {str(data)[:200]}") from exc

        self._messages.append({"role": "assistant", "content": content})

        obj = _extract_json_object(content)
        if not obj:
            # Couldn't parse — ask the loop to stop cleanly rather than guess.
            return Move(kind="abort",
                        rationale=f"Qwen did not return parseable JSON: {content[:80]!r}",
                        decision=Decision.ABORT)

        move = str(obj.get("move", "abort")).lower().strip()
        rationale = str(obj.get("rationale", "")).strip()
        self._last_rationale = rationale

        if move == "attack":
            raw = obj.get("payload")
            if not raw:
                return Move(kind="conclude_safe",
                            rationale="Qwen chose attack but produced no payload.",
                            decision=Decision.CONCLUDE_SAFE)
            return Move(
                kind="attack",
                payload=Payload(value=str(raw), name="qwen", technique=scenario.kind,
                                context="model-generated", note=rationale),
                rationale=rationale or "Qwen-generated vector.",
                decision=Decision.RE_ATTACK,
            )
        if move in ("conclude_vulnerable", "vulnerable"):
            return Move(kind="conclude_vulnerable", rationale=rationale, decision=Decision.CONCLUDE_VULNERABLE)
        if move in ("conclude_safe", "safe"):
            return Move(kind="conclude_safe", rationale=rationale, decision=Decision.CONCLUDE_SAFE)
        return Move(kind="abort", rationale=rationale or "Qwen aborted.", decision=Decision.ABORT)

    def rectify(self, state: EngagementState, obs: Observation, console) -> Rectification:
        # Feed the captured result back so the NEXT propose() sees it.
        feedback = (
            "RESULT of the last payload (JSON): "
            + _result_feedback(obs)
            + " Decide the next move as JSON."
        )
        self._messages.append({"role": "user", "content": feedback})

        if obs.signal:
            return Rectification(Decision.ESCALATE, self._last_rationale or "Signal observed; concluding.")
        if not obs.ok:
            return Rectification(Decision.MUTATE, f"Qwen will adjust after: {obs.error}")
        return Rectification(Decision.NEW_PATH, "Survived; Qwen will pick a new vector.")


def _result_feedback(obs: Observation) -> str:
    import json

    return json.dumps({
        "ok": obs.ok,
        "signal": obs.signal,
        "error": obs.error or None,
        "detail": obs.signal_detail or None,
        "status": obs.evidence.get("status"),
        "reflected": obs.evidence.get("reflected"),
        "marker": obs.evidence.get("marker"),
        "sql_error": obs.evidence.get("sql_error"),
    })


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def make_strategist(name: str, model: Optional[str] = None,
                    base_url: Optional[str] = None, use_hints: bool = True) -> Strategist:
    name = (name or "rule").lower()
    if name in ("rule", "rules", "playbook", "auto"):
        return RuleBasedStrategist()
    if name in ("claude", "anthropic"):
        return ClaudeStrategist(model=model)
    if name in ("qwen", "ollama", "openai", "openai-compat", "local", "vllm"):
        return QwenStrategist(model=model, base_url=base_url, use_hints=use_hints)
    if name in ("human", "manual", "me"):
        return HumanStrategist()
    raise ValueError(f"Unknown strategist {name!r}. Use rule | qwen | claude | human.")
