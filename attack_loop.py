#!/usr/bin/env python3
"""
attack_loop.py — the primary execution script for the Iterative Attack Loop.

    LLM plans -> harness fires -> Ubuntu returns stdout/stderr ->
    LLM rectifies -> ... -> VERDICT (VULNERABLE | SAFE)

Run `python3 attack_loop.py --help` for options, or see README.md.

AUTHORIZED TESTING ONLY. Point this at systems you own or have written
permission to test. Non-localhost targets require explicit authorization.
"""

from __future__ import annotations

import argparse
import sys

from core.browser import make_driver, DriverError
from core.console import Console
from core.executor import CommandExecutor, ExecutionBlocked
from core.loop import AttackLoop
from core.report import ReportWriter
from core.scope import ScopeGuard
from core.strategist import make_strategist
from scenarios import available, build_scenario


DEFAULT_URL = "http://127.0.0.1:5000/"


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack_loop.py",
        description="Iterative, headed attack loop for AUTHORIZED security testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  # demo against the bundled vulnerable target (headed browser)\n"
            "  python3 attack_loop.py --scenario reflected-xss\n\n"
            "  # let a local Qwen (via Ollama) GENERATE every payload live\n"
            "  ollama serve &  ollama pull qwen2.5-coder:7b\n"
            "  python3 attack_loop.py --scenario sqli-login --strategist qwen\n\n"
            "  # let Claude drive the loop instead\n"
            "  ANTHROPIC_API_KEY=... python3 attack_loop.py --scenario sqli-login --strategist claude\n\n"
            "  # you are the brain: paste each result into your own LLM\n"
            "  python3 attack_loop.py --scenario reflected-xss --strategist human\n\n"
            "  # point at your own app (requires authorization for non-localhost)\n"
            "  python3 attack_loop.py --scenario sqli-login --url https://staging.example.com/login \\\n"
            "      --authorize-host staging.example.com\n"
        ),
    )
    p.add_argument("--scenario", default="reflected-xss",
                   help=f"technique to run. choices: {', '.join(available())}")
    p.add_argument("--url", default=DEFAULT_URL, help=f"target base URL (default {DEFAULT_URL})")
    p.add_argument("--driver", default="playwright",
                   help="playwright (real headed browser) | http (no-browser probe)")
    p.add_argument("--strategist", default="rule",
                   help="rule (playbook) | qwen (LLM-generated payloads) | claude (API) | human (paste-in)")
    p.add_argument("--max-iterations", type=int, default=12)
    p.add_argument("--model", default=None,
                   help="model id for an LLM brain (Claude model, or Qwen tag e.g. qwen2.5-coder:7b)")
    p.add_argument("--base-url", default=None,
                   help="OpenAI-compatible endpoint for --strategist qwen "
                        "(default $QWEN_BASE_URL or http://localhost:11434/v1)")
    p.add_argument("--no-hints", action="store_true",
                   help="for --strategist qwen: do not even show example payloads; model invents everything")

    # headed browser behaviour
    p.add_argument("--headless", action="store_true", help="run the browser headless (default: headed/visible)")
    p.add_argument("--slow-mo", type=int, default=350, help="ms delay between browser actions so you can watch")

    # scope / authorization
    p.add_argument("--authorize-host", action="append", default=[],
                   help="mark a non-local host as authorized (repeatable)")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="assert written authorization for all targets (skips the prompt)")
    p.add_argument("--yes", action="store_true", help="non-interactive; never prompt")

    # scenario field overrides (so it works on YOUR app, not just the demo)
    p.add_argument("--login-path", default=None)
    p.add_argument("--search-path", default=None)
    p.add_argument("--query-field", default=None)
    p.add_argument("--user-selector", default=None)
    p.add_argument("--pass-selector", default=None)
    p.add_argument("--submit-selector", default=None)
    p.add_argument("--login-user", default=None)
    p.add_argument("--login-pass", default=None)
    p.add_argument("--no-login", action="store_true", help="skip the auth step (reflected-xss)")

    # feedback-phase demo: run a real Ubuntu recon command first
    p.add_argument("--recon-cmd", default=None,
                   help="optional shell command run before the loop (demonstrates stdout/stderr capture)")
    p.add_argument("--allow-dangerous", action="store_true",
                   help="disable the executor's destructive-command guard (not recommended)")

    # output
    p.add_argument("--report-dir", default="engagements")
    p.add_argument("--no-report", action="store_true")
    p.add_argument("--screenshots", default=None, help="dir to save screenshots on a signal")
    p.add_argument("--no-color", action="store_true")

    # utility modes
    p.add_argument("--list-scenarios", action="store_true")
    p.add_argument("--selfcheck", action="store_true", help="report which optional deps are installed")
    return p


# ---------------------------------------------------------------------------
# utility modes
# ---------------------------------------------------------------------------
def do_selfcheck(console: Console) -> int:
    console.banner("SELF CHECK", "optional dependencies")
    checks = [
        ("rich (pretty terminal)", "rich"),
        ("playwright (headed browser)", "playwright"),
        ("requests (http driver)", "requests"),
        ("anthropic (claude strategist)", "anthropic"),
        ("flask (bundled demo target)", "flask"),
    ]
    import importlib
    all_ok = True
    for label, mod in checks:
        try:
            importlib.import_module(mod)
            console.observe(f"OK   {label}")
        except Exception:
            all_ok = False
            console.error(f"MISS {label}  (pip install {mod})")

    # browser binaries are separate from the python package
    try:
        import importlib
        importlib.import_module("playwright")
        console.info("note: run 'playwright install chromium' to fetch the browser binary")
    except Exception:
        pass

    console.info("rule-based strategist + http driver need nothing beyond the stdlib + requests")
    return 0 if all_ok else 1


def scenario_kwargs(args) -> dict:
    """Translate CLI flags into scenario constructor overrides."""
    kw = dict(
        login_path=args.login_path,
        search_path=args.search_path,
        query_field=args.query_field,
        user_selector=args.user_selector,
        pass_selector=args.pass_selector,
        submit_selector=args.submit_selector,
        username=args.login_user,
        password=args.login_pass,
    )
    if args.no_login:
        kw["needs_login"] = False
    return kw


def run_recon(cmd: str, console: Console, allow_dangerous: bool) -> None:
    """Demonstrate the Feedback Phase on a real Ubuntu command before attacking."""
    console.action(f"Recon command: {cmd}")
    executor = CommandExecutor(allow_dangerous=allow_dangerous)
    try:
        obs = executor.run(cmd)
    except ExecutionBlocked as exc:
        console.error(str(exc))
        return
    if obs.ok:
        first = (obs.stdout.strip().splitlines() or ["(no output)"])[0]
        console.observe(f"exit=0  {first}")
    else:
        console.error(f"exit={obs.returncode}  {obs.error}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(colour=False if args.no_color else None)

    if args.list_scenarios:
        console.banner("SCENARIOS")
        for name in available():
            console.info(name)
        return 0

    if args.selfcheck:
        return do_selfcheck(console)

    if args.scenario not in available():
        console.error(f"Unknown scenario {args.scenario!r}. Available: {', '.join(available())}")
        return 2

    # build the pieces --------------------------------------------------
    try:
        scenario = build_scenario(args.scenario, args.url, **scenario_kwargs(args))
    except KeyError as exc:
        console.error(str(exc))
        return 2

    try:
        strategist = make_strategist(
            args.strategist, model=args.model,
            base_url=args.base_url, use_hints=not args.no_hints,
        )
    except ValueError as exc:
        console.error(str(exc))
        return 2

    try:
        driver = make_driver(args.driver, headless=args.headless, slow_mo_ms=args.slow_mo)
    except DriverError as exc:
        console.error(str(exc))
        return 2

    scope = ScopeGuard(
        authorized_hosts=args.authorize_host,
        blanket_authorization=args.i_have_authorization,
        assume_yes=args.yes,
        interactive=not args.yes,
    )

    if args.recon_cmd:
        run_recon(args.recon_cmd, console, args.allow_dangerous)

    loop = AttackLoop(
        scenario=scenario,
        driver=driver,
        strategist=strategist,
        console=console,
        scope=scope,
        max_iterations=args.max_iterations,
        screenshot_dir=args.screenshots,
    )

    try:
        state = loop.run()
    except Exception as exc:  # pragma: no cover - last-resort guard
        console.error(f"Unhandled error: {type(exc).__name__}: {exc}")
        return 3

    if not args.no_report:
        folder = ReportWriter(args.report_dir).write(state)
        console.info(f"report written to {folder}/")

    # exit code encodes the verdict so CI / scripts can branch on it
    from core.models import Verdict
    return {
        Verdict.VULNERABLE: 1,   # found something -> non-zero so CI fails loudly
        Verdict.SAFE: 0,
        Verdict.INCONCLUSIVE: 0,
        Verdict.ABORTED: 2,
        Verdict.PENDING: 2,
    }[state.verdict]


if __name__ == "__main__":
    sys.exit(main())
