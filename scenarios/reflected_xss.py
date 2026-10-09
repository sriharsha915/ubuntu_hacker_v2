"""Reflected XSS scenario.

Flow:
    [ACTION] open + navigate   (done by the loop around driver.start)
    [INPUT]  log in            (optional; the search page may require auth)
    [ATTACK] fire payload at the reflected parameter
    [OBSERVE]/[ERROR]/[SIGNAL] classify the response

A win is an actual alert() dialog (real browser) OR the raw payload reflected
into the HTML without encoding (http probe can only reach this weaker signal).
"""

from __future__ import annotations

from typing import List

from core.models import Observation, Payload
from core.payloads import XSS_PAYLOADS
from .base import Scenario


class ReflectedXssScenario(Scenario):
    kind = "reflected-xss"

    DEFAULTS = dict(
        search_path="/search",
        query_field="q",
        needs_login=True,
        login_path="/",
        login_action="/login",
        user_selector="input[name=username]",
        pass_selector="input[name=password]",
        submit_selector="button[type=submit]",
        username="admin",
        password="s3cr3t",
        component="search field (q)",
        name="reflected-xss on /search",
    )

    def __init__(self, base_url: str, **params):
        merged = {**self.DEFAULTS, **params}
        super().__init__(base_url, **merged)

    def signal_description(self) -> str:
        return ("an alert() dialog fires (real browser) or the raw payload is "
                "reflected into the HTML without escaping")

    def preflight(self, driver, console) -> None:
        if not self.params.get("needs_login"):
            return
        login_url = self.url(self.params["login_path"])
        console.input_(
            f"Entering credentials for '{self.params['username']}' at {login_url}"
        )
        res = driver.login(
            login_url,
            self.params["user_selector"], self.params["username"],
            self.params["pass_selector"], self.params["password"],
            submit=self.params["submit_selector"],
            action_url=self.url(self.params["login_action"]),
        )
        if res.error:
            console.error(f"Login step error: {res.error}")
        else:
            console.observe(f"Authenticated; landed on {res.url}")

    def candidate_payloads(self) -> List[Payload]:
        return list(XSS_PAYLOADS)

    def attempt(self, driver, console, payload: Payload) -> Observation:
        search_url = self.url(self.params["search_path"])
        field = self.params["query_field"]
        console.attack(
            f"Firing '{payload.name}' at {field}= ({payload.length} chars): {payload.short()}"
        )
        res = driver.probe_get(search_url, {field: payload.value})

        # driver/transport error -------------------------------------------
        if res.error:
            return Observation(ok=False, error=res.error,
                               evidence={"status": res.status})

        # target rejected it (length guard, 400, ...) ----------------------
        too_long = self._looks_too_long(res)
        if too_long:
            console.observe(f"Rejected: {too_long}")
            return Observation(ok=False, error=too_long,
                               evidence={"status": res.status, "reflected": False})

        # proof of execution (real browser dialog) -------------------------
        if res.dialog and "alert" in res.dialog.lower():
            detail = f"JavaScript dialog fired -> {res.dialog}"
            console.signal(detail)
            return Observation(ok=True, signal=True, signal_detail=detail,
                               evidence={"status": res.status, "dialog": res.dialog,
                                         "reflected": True})

        # weaker signal: reflected unescaped -------------------------------
        reflected = self._reflected_unescaped(payload.value, res.html)
        if reflected and not driver.can_prove_execution:
            detail = "Payload reflected into HTML unescaped (execution not proven without a browser)"
            console.signal(detail)
            return Observation(ok=True, signal=True, signal_detail=detail,
                               evidence={"status": res.status, "reflected": True})

        if reflected:
            # Reflected raw but no dialog fired in a real browser -> context
            # likely non-executing (e.g. inside a textarea/comment).
            console.observe("Reflected unescaped but no dialog fired; context may not execute.")
            return Observation(ok=True, signal=False,
                               evidence={"status": res.status, "reflected": True})

        console.observe("Payload neutralised (escaped / not reflected).")
        return Observation(ok=True, signal=False,
                           evidence={"status": res.status, "reflected": False})
