#!/usr/bin/env python3
"""
Deterministic tests for the attack loop — no browser, no server, no network.

A FakeDemoDriver mimics the bundled vulnerable target's behaviour so we can
assert the end-to-end state machine (propose -> act -> observe -> rectify ->
verdict) without any optional dependency.

Run:
    python3 tests/test_loop.py          # built-in runner
    python3 -m pytest tests/            # if pytest is installed
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.browser import PageResult
from core.console import Console
from core.executor import CommandExecutor, ExecutionBlocked
from core.loop import AttackLoop
from core.models import Verdict
from core.payloads import XSS_PAYLOADS
from core.scope import ScopeGuard, ScopeError
from core.strategist import (
    RuleBasedStrategist,
    QwenStrategist,
    make_strategist,
    _extract_json_object,
)
from scenarios import build_scenario


QUIET = Console(colour=False)


class FakeDemoDriver:
    """Replicates vulnerable_app.py semantics in-process."""

    def __init__(self, can_prove_execution=True, maxlen=30):
        self.kind = "browser" if can_prove_execution else "http"
        self.can_prove_execution = can_prove_execution
        self.maxlen = maxlen
        self.started = False

    def start(self):
        self.started = True

    def stop(self):
        self.started = False

    def pop_dialog(self):
        return None

    def login(self, url, user_field, user, pass_field, password, submit=None, action_url=None):
        # valid creds OR a SQLi comment-bypass -> authenticated
        bypass = "--" in user
        valid = (user == "admin" and password == "s3cr3t")
        if bypass or valid:
            return PageResult(url=url + "dashboard", status=200,
                              html="<h1>Welcome, admin</h1><a href='/logout'>Logout</a>")
        return PageResult(url=url, status=401, html="<h1>Invalid credentials</h1>")

    def probe_get(self, url, params):
        q = params.get("q", "")
        if len(q) > self.maxlen:
            return PageResult(url=url, status=400,
                              html=f"Search query too long (max {self.maxlen} characters).")
        html = f"<h1>Search</h1><p>Results for: {q}</p>"
        dialog = None
        if self.can_prove_execution and any(
            h in q for h in ("onerror", "onload", "onclick", "<script")
        ):
            dialog = "alert: 1"
        return PageResult(url=url, status=200, html=html, dialog=dialog)

    def screenshot(self, path):
        return None


class XssLoopTest(unittest.TestCase):
    def test_reflected_xss_reaches_vulnerable_after_shortening(self):
        scenario = build_scenario("reflected-xss", "http://127.0.0.1:5000/")
        loop = AttackLoop(
            scenario=scenario,
            driver=FakeDemoDriver(can_prove_execution=True),
            strategist=RuleBasedStrategist(),
            console=QUIET,
            scope=ScopeGuard(),
            max_iterations=12,
        )
        state = loop.run()
        self.assertEqual(state.verdict, Verdict.VULNERABLE)
        self.assertTrue(state.findings)
        # The first attempt must have been rejected for length -> proves the
        # [ERROR] -> [RECTIFY] shorten path actually ran.
        errors = [s.observation.error for s in state.steps if s.observation and s.observation.error]
        self.assertTrue(any("too long" in e.lower() for e in errors), errors)
        # And it won quickly once shortened.
        self.assertLessEqual(state.iterations, 4)

    def test_http_probe_reaches_vulnerable_via_reflection(self):
        scenario = build_scenario("reflected-xss", "http://127.0.0.1:5000/")
        loop = AttackLoop(
            scenario=scenario,
            driver=FakeDemoDriver(can_prove_execution=False),  # no dialogs
            strategist=RuleBasedStrategist(),
            console=QUIET,
            scope=ScopeGuard(),
        )
        state = loop.run()
        self.assertEqual(state.verdict, Verdict.VULNERABLE)


class SqliLoopTest(unittest.TestCase):
    def test_sqli_login_auth_bypass(self):
        scenario = build_scenario("sqli-login", "http://127.0.0.1:5000/")
        loop = AttackLoop(
            scenario=scenario,
            driver=FakeDemoDriver(),
            strategist=RuleBasedStrategist(),
            console=QUIET,
            scope=ScopeGuard(),
        )
        state = loop.run()
        self.assertEqual(state.verdict, Verdict.VULNERABLE)
        self.assertEqual(state.findings[0].severity, "critical")


class SafeVerdictTest(unittest.TestCase):
    def test_component_that_survives_is_safe(self):
        class HardenedDriver(FakeDemoDriver):
            def probe_get(self, url, params):
                import html as _h
                q = params.get("q", "")
                if len(q) > self.maxlen:
                    return PageResult(url=url, status=400, html="too long")
                # properly escaped -> no execution, no raw reflection
                return PageResult(url=url, status=200,
                                  html=f"<p>Results for: {_h.escape(q)}</p>")

        scenario = build_scenario("reflected-xss", "http://127.0.0.1:5000/")
        loop = AttackLoop(
            scenario=scenario,
            driver=HardenedDriver(can_prove_execution=True),
            strategist=RuleBasedStrategist(),
            console=QUIET,
            scope=ScopeGuard(),
        )
        state = loop.run()
        self.assertEqual(state.verdict, Verdict.SAFE)
        self.assertFalse(state.findings)


class FakeQwen(QwenStrategist):
    """QwenStrategist with the HTTP boundary stubbed out by canned replies."""

    def __init__(self, replies):
        super().__init__()
        self._replies = list(replies)
        self.sent = []

    def _post(self, body):
        self.sent.append(body)                       # capture what we'd send
        content = self._replies.pop(0)
        return {"choices": [{"message": {"content": content}}]}


class QwenLoopTest(unittest.TestCase):
    def test_qwen_generated_payloads_drive_the_loop(self):
        # Qwen "invents" the payloads; none are hardcoded in our code.
        replies = [
            '{"move":"attack","payload":"\' OR \'1\'=\'1","rationale":"tautology"}',
            '```json\n{"move":"attack","payload":"admin\' -- ","rationale":"comment out the password check"}\n```',
        ]
        brain = FakeQwen(replies)
        scenario = build_scenario("sqli-login", "http://127.0.0.1:5000/")
        loop = AttackLoop(
            scenario=scenario,
            driver=FakeDemoDriver(),
            strategist=brain,
            console=QUIET,
            scope=ScopeGuard(),
        )
        state = loop.run()
        self.assertEqual(state.verdict, Verdict.VULNERABLE)
        # The payload that won must be exactly what the model returned.
        self.assertEqual(state.findings[0].payload, "admin' -- ")
        # And the model actually saw the first result fed back before turn 2.
        self.assertGreaterEqual(len(brain.sent), 2)
        turn2_msgs = brain.sent[1]["messages"]
        self.assertTrue(any("RESULT of the last payload" in m["content"]
                            for m in turn2_msgs if m["role"] == "user"))

    def test_qwen_can_declare_safe(self):
        brain = FakeQwen(['{"move":"conclude_safe","rationale":"nothing worked"}'])
        scenario = build_scenario("reflected-xss", "http://127.0.0.1:5000/")
        loop = AttackLoop(scenario=scenario, driver=FakeDemoDriver(),
                          strategist=brain, console=QUIET, scope=ScopeGuard())
        state = loop.run()
        self.assertEqual(state.verdict, Verdict.SAFE)


class JsonExtractionTest(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(_extract_json_object('{"move":"abort"}')["move"], "abort")

    def test_fenced_json(self):
        obj = _extract_json_object('```json\n{"move":"attack","payload":"x"}\n```')
        self.assertEqual(obj["payload"], "x")

    def test_json_with_prose_around_it(self):
        obj = _extract_json_object('Sure! {"move":"attack","payload":"<svg>"} hope that helps')
        self.assertEqual(obj["payload"], "<svg>")

    def test_garbage_returns_none(self):
        self.assertIsNone(_extract_json_object("not json at all"))


class ScopeTest(unittest.TestCase):
    def test_localhost_is_allowed(self):
        ScopeGuard().authorize("http://127.0.0.1:5000/")  # no raise

    def test_remote_requires_authorization(self):
        with self.assertRaises(ScopeError):
            ScopeGuard(assume_yes=True, interactive=False).authorize("https://example.com/")

    def test_remote_with_blanket_auth_ok(self):
        ScopeGuard(blanket_authorization=True).authorize("https://example.com/")

    def test_remote_with_host_allowlist_ok(self):
        ScopeGuard(authorized_hosts=["example.com"]).authorize("https://example.com/login")


class ExecutorTest(unittest.TestCase):
    def test_blocks_destructive_command(self):
        with self.assertRaises(ExecutionBlocked):
            CommandExecutor().run("rm -rf / ")

    def test_captures_stdout_and_returncode(self):
        obs = CommandExecutor().run(sys.executable + " -c \"print('hello')\"")
        self.assertTrue(obs.ok)
        self.assertIn("hello", obs.stdout)
        self.assertEqual(obs.returncode, 0)

    def test_captures_failure(self):
        obs = CommandExecutor().run(sys.executable + " -c \"import sys; sys.exit(7)\"")
        self.assertFalse(obs.ok)
        self.assertEqual(obs.returncode, 7)


class InvariantTest(unittest.TestCase):
    """Lock the numbers the demo narrative depends on."""

    def test_payload_length_invariants(self):
        by_name = {p.name: p for p in XSS_PAYLOADS}
        # The first vector must exceed the demo's 30-char guard...
        self.assertGreater(by_name["classic-script"].length, 30)
        # ...and there must be a working vector under it.
        self.assertLessEqual(by_name["img-onerror"].length, 30)

    def test_strategist_factory(self):
        self.assertEqual(make_strategist("rule").name, "rule")
        self.assertEqual(make_strategist("human").name, "human")
        self.assertEqual(make_strategist("claude").name, "claude")


def _run() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(_run())
