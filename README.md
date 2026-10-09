# Iterative Attack Loop

A **headed**, LLM-in-the-loop harness for **authorized** web-application security testing.

```
  plan  ──▶  act  ──▶  observe  ──▶  rectify  ──▶ … ──▶  VERDICT
 (brain)   (hands)   (feedback)    (brain)              SAFE | VULNERABLE
```

The brain proposes a move (a payload or a decision). The harness performs it in
a **real, visible browser** (or a no-browser probe) and on **Ubuntu's shell**,
captures everything (`stdout`, `stderr`, dialogs, HTTP responses), and feeds the
result back to the brain. The brain rectifies — *re-attack, mutate, or try a new
path* — and the loop repeats until it reaches a verdict: the component is **SAFE**
(it survived every vector) or **VULNERABLE** (a signal was proven, e.g. an
`alert()` dialog actually fired).

The terminal reads as a linear story, not a wall of text:

```
[ACTION]  Opening browser driver (headed browser)...
[INPUT]   Entering credentials for 'admin' at http://127.0.0.1:5000/
[OBSERVE] Authenticated; landed on http://127.0.0.1:5000/dashboard
[ATTACK]  Firing 'classic-script' at q= (39 chars): <script>alert(document.domain)</script>
[OBSERVE] Rejected: Search query too long (max 30 characters). You sent 39.
[RECTIFY] Payload too long for field (limit 30 chars). Dropping 2 oversized vector(s); shortening to <img src=x onerror=alert(1)>.
[ATTACK]  Firing 'img-onerror' at q= (28 chars): <img src=x onerror=alert(1)>
[SIGNAL]  JavaScript dialog fired -> alert: 1
[VERDICT] VULNERABLE
```

---

## ⚠ Authorized use only

This is a dual-use tool. **Only point it at systems you own or have explicit,
written permission to test.** Guardrails are built in, not bolted on:

- **Scope guard** — non-`localhost` targets are refused unless you pass
  `--authorize-host <host>` or `--i-have-authorization`, or confirm interactively.
- **Executor denylist** — obviously destructive shell commands (`rm -rf /`,
  `mkfs`, `curl … | bash`, fork bombs, …) are refused unless you pass
  `--allow-dangerous`.
- **Audit trail** — every run writes a timestamped report under `engagements/`.
- **The bundled target binds to `127.0.0.1` only** and refuses to go public.

You are responsible for staying in scope and within the law.

---

## Quick start (Ubuntu)

```bash
# 1. set everything up (venv, deps, headed browser binary)
./scripts/install.sh
source .venv/bin/activate

# 2. (optional) handy aliases
source scripts/aliases.sh

# 3. launch the bundled, intentionally-vulnerable practice target
./scripts/start_target.sh &          # http://127.0.0.1:5000  (admin / s3cr3t)

# 4. run the loop — watch the browser open and the alert() fire
./scripts/run.sh --scenario reflected-xss
./scripts/run.sh --scenario sqli-login
```

No API key is needed: the default **rule-based brain** runs offline. Check your
install any time with `./scripts/run.sh --selfcheck`.

> **Zero-dependency path:** the deterministic brain plus the no-browser probe
> need only `requests`:
> `python3 attack_loop.py --scenario reflected-xss --driver http`

---

## The four brains (`--strategist`)

| value    | what it is                        | needs                     |
|----------|-----------------------------------|---------------------------|
| `rule`   | deterministic payload playbook (default) | nothing            |
| `qwen`   | **Qwen generates every payload live** via any OpenAI-compatible endpoint | an endpoint (e.g. Ollama) + `requests` |
| `claude` | a real closed loop driven by the Anthropic API | `anthropic`, `ANTHROPIC_API_KEY` |
| `human`  | **you** are the brain — paste each result into your own LLM | nothing |

### `qwen` — the LLM generates the payloads (nothing hardcoded)

This is the "you say SQLi, the model returns the payloads" loop. Each turn the
harness sends Qwen the objective + the running transcript; Qwen replies with a
JSON move `{move, payload, rationale}`; the `payload` is dropped straight into
the target's form-field placeholder and fired; the captured result is fed back,
and Qwen produces the next one. **No payload is hardcoded** — they all come from
the model. (The field *selectors* — which input to type into — are target
structure you configure, not attack values.)

```bash
# 1. run a local Qwen (Ollama is the easy path)
ollama serve &
ollama pull qwen2.5-coder:7b

# 2. point the loop at it
python3 attack_loop.py --scenario sqli-login --strategist qwen
python3 attack_loop.py --scenario reflected-xss --strategist qwen --no-hints
```

Configure the endpoint/model via flags or env:

| flag / env                      | default                        |
|---------------------------------|--------------------------------|
| `--base-url` / `QWEN_BASE_URL`  | `http://localhost:11434/v1` (Ollama) |
| `--model` / `QWEN_MODEL`        | `qwen2.5-coder:7b`             |
| `QWEN_API_KEY`                  | `ollama` (use a real key for DashScope / OpenRouter) |
| `--no-hints`                    | omit even example vectors; the model invents everything |

Because it speaks the standard OpenAI `/v1/chat/completions` API, the same brain
works against **vLLM, LM Studio, DashScope, OpenRouter**, or any compatible
server — just change `--base-url` and `--model`.

Live transcript (Qwen choosing and generating each payload):

```
[PLAN]    start with a tautology
[INPUT]   Username <- '' OR '1'='1'  |  password <- 'x'
[OBSERVE] Login rejected; no SQL error, no bypass.
[RECTIFY] Survived; Qwen will pick a new vector.
[PLAN]    comment out the password check
[INPUT]   Username <- 'admin' -- '  |  password <- 'x'
[SIGNAL]  Authenticated area reached without valid creds (marker: 'logout')
[VERDICT] VULNERABLE
```

### `claude`

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-opus-4-8        # or your preferred current model
python3 attack_loop.py --scenario sqli-login --strategist claude
```

The Claude brain uses a **forced tool call** for its move each turn (structured
`{move, payload, rationale}`, no fragile text parsing), and the harness feeds
each result back as a `tool_result` so the model keeps a running memory.

---

## The two drivers (`--driver`)

| value        | what it is                                   | proves execution? |
|--------------|----------------------------------------------|-------------------|
| `playwright` | a **real, headed** Chromium (default)        | ✅ catches real `alert()` dialogs |
| `http`       | a no-browser `requests` probe                | ⚠ reflection / SQL-error / auth-bypass only |

Use `--headless` to hide the browser, `--slow-mo <ms>` to slow actions down so
you can watch. The `http` driver is for headless boxes, CI, or a quick pass
before you've installed browsers.

---

## How to feed errors back into the LLM

### Automated (`--strategist claude`)
The harness does it for you. Each turn it hands the model the objective and the
full transcript, the model returns the next move, the harness fires it and feeds
the captured result straight back. You just watch.

### Manual (`--strategist human`) — bring your own LLM
Run the loop in `human` mode. After each attempt it prints a ready-to-paste
block:

```
================= FEED THIS BACK TO THE LLM =================
OBJECTIVE : reflected-xss on /search (reflected-xss)
TARGET    : http://127.0.0.1:5000/
LAST ATTEMPT
  ok        : False
  error     : Search query too long (max 30 characters). You sent 39.
PAYLOADS ALREADY TRIED
  - <script>alert(document.domain)</script>
ASK
  Given the objective and the last result, what is the single best next
  payload to try? Reply with ONLY the raw payload on one line, or SAFE / VULN.
============================================================
  Paste next payload (or SAFE / VULN / quit):
```

Copy it into ChatGPT / Claude / your LLM of choice, paste the suggested payload
back at the prompt, and the loop continues. Type `SAFE`, `VULN`, or `quit` to end.

### Manual (any command) — `scripts/feedback.sh`
For free-form shell testing (`curl`, `sqlmap`, `nmap`, …), wrap any command to
capture its output in an LLM-ready block:

```bash
./scripts/feedback.sh curl -s 'http://127.0.0.1:5000/search?q=<svg onload=alert(1)>'
```

It prints the command, exit code, `stdout`, `stderr`, and a ready-made "what's
the next step?" prompt (also saved under `engagements/feedback/`). Paste it into
your LLM, take its suggestion, run it through `feedback.sh` again — **that is the
loop.** You can also prepend a recon command to any run with
`--recon-cmd "<cmd>"` to see the executor capture `stdout`/`stderr` first-hand.

---

## Point it at your own app

The scenarios default to the bundled target but every selector is overridable:

```bash
python3 attack_loop.py \
  --scenario sqli-login \
  --url https://staging.example.com/ \
  --login-path /login \
  --user-selector 'input[name=email]' \
  --pass-selector 'input[name=password]' \
  --submit-selector 'button[type=submit]' \
  --authorize-host staging.example.com      # required: assert authorization
```

For reflected XSS, point `--search-path` / `--query-field` at the reflected
parameter, and pass `--no-login` if the page is public. See `--help` for the
full flag list.

---

## Event tags

| tag         | meaning                                             |
|-------------|-----------------------------------------------------|
| `[ACTION]`  | opening a browser, navigating, running a command    |
| `[INPUT]`   | entering credentials / filling a field              |
| `[PLAN]`    | the brain announcing what it will try               |
| `[ATTACK]`  | crafting / firing a payload                          |
| `[OBSERVE]` | what came back                                      |
| `[ERROR]`   | the attempt failed (rejected, tool error)           |
| `[RECTIFY]` | the brain adjusting the path                        |
| `[SIGNAL]`  | a vulnerability signal was detected                 |
| `[VERDICT]` | the final conclusion                                |

Output is colourised with `rich` when installed, and falls back to plain ANSI
(or no colour under `--no-color` / `NO_COLOR`).

---

## Verdicts & exit codes

| verdict        | exit code | meaning                                        |
|----------------|-----------|------------------------------------------------|
| `VULNERABLE`   | `1`       | a signal was proven (fails CI loudly on purpose)|
| `SAFE`         | `0`       | every vector in scope was tried and survived    |
| `INCONCLUSIVE` | `0`       | ran out of the `--max-iterations` budget first  |
| `ABORTED`      | `2`       | scope refused, driver/brain error, or `quit`    |

Each run writes `engagements/<timestamp>-<scenario>/report.json` (full machine
state: every step, payload, and observation) and `report.md` (a summary you can
paste into a ticket).

---

## Project layout

```
attack_loop.py            # the primary CLI / orchestrator
core/
  models.py               # dataclasses + enums (Action, Observation, Verdict, …)
  console.py              # the tagged terminal renderer ([ACTION], [ATTACK], …)
  scope.py                # authorization / scope guard
  executor.py             # Feedback Phase: run shell commands, capture stdout/stderr
  browser.py              # Action Phase: headed Playwright driver + HTTP probe
  payloads.py             # XSS / SQLi payload libraries
  strategist.py           # Rectification Phase: rule / claude / human brains
  loop.py                 # the AttackLoop state machine
  report.py               # engagement report writer (JSON + Markdown)
scenarios/
  reflected_xss.py        # reflected-XSS technique
  sqli_login.py           # SQLi auth-bypass technique
  __init__.py             # scenario registry (add your own here)
targets/
  vulnerable_app.py       # the bundled, localhost-only practice target
scripts/
  install.sh  run.sh  start_target.sh  feedback.sh  aliases.sh
tests/
  test_loop.py            # deterministic tests (no browser/server needed)
```

### Add your own technique

1. Subclass `scenarios.base.Scenario`, implement `candidate_payloads()` and
   `attempt(driver, console, payload) -> Observation`, and set `signal=True` on
   the Observation when you detect your win condition.
2. Register it in `scenarios/__init__.py`.

Every brain and driver works with it automatically.

---

## The bundled target

`targets/vulnerable_app.py` is a ~120-line Flask app that is **intentionally
vulnerable** (string-concatenated SQL login + an unescaped reflected search
parameter with a short length guard, so you can watch the loop *shorten* a
payload). It binds to `127.0.0.1` only and refuses to go public. It exists so you
can watch the loop win against a safe, self-owned target — think DVWA / Juice
Shop, but tiny. **Never deploy it.**

---

## Tests

```bash
python3 tests/test_loop.py        # built-in runner, no dependencies
python3 -m pytest tests/          # if pytest is installed
```

The tests drive the full state machine with a fake in-process target, so they
assert the loop's behaviour (shorten-on-too-long, auth bypass, SAFE on a
hardened component, scope refusal, the executor denylist) without a browser,
server, or network.
