"""The Action Phase: drive a target the way a tester would.

Two interchangeable drivers implement the same small, web-form-shaped API:

* PlaywrightDriver - a REAL, headed browser. You *see* it open, type, and pop
  alert() dialogs. This is the "headed experience" the brief asks for and the
  only driver that can *prove* script execution (a real alert() firing).

* HttpProbe - no browser at all (just `requests`). It can't prove execution,
  only reflection / SQL-error / auth-bypass signals. It exists so the loop
  still runs on a headless box, in CI, or before you've installed browsers.

Both expose:
    start() / stop()
    login(url, user_field, user, pass_field, password, submit=None) -> PageResult
    submit_form(url, fields, submit=None, method="get") -> PageResult
    probe_get(url, params) -> PageResult
    pop_dialog() -> Optional[str]
    screenshot(path) -> Optional[str]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlencode


@dataclass
class PageResult:
    url: str = ""
    status: Optional[int] = None
    html: str = ""
    dialog: Optional[str] = None
    error: str = ""


class DriverError(Exception):
    pass


# ---------------------------------------------------------------------------
# Headed real browser
# ---------------------------------------------------------------------------
class PlaywrightDriver:
    kind = "browser"
    can_prove_execution = True

    def __init__(self, headless: bool = False, slow_mo_ms: int = 350, browser: str = "chromium"):
        self.headless = headless
        self.slow_mo_ms = slow_mo_ms
        self.browser_name = browser
        self._pw = None
        self._browser = None
        self._page = None
        self._dialogs: List[str] = []

    # lifecycle -------------------------------------------------------------
    def start(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover
            raise DriverError(
                "Playwright is not installed. Run scripts/install.sh, or use "
                "--driver http for the no-browser probe."
            ) from exc
        self._pw = sync_playwright().start()
        launcher = getattr(self._pw, self.browser_name)
        try:
            self._browser = launcher.launch(headless=self.headless, slow_mo=self.slow_mo_ms)
        except Exception as exc:  # pragma: no cover
            raise DriverError(
                f"Could not launch {self.browser_name}. Did 'playwright install "
                f"{self.browser_name}' run? Original error: {exc}"
            ) from exc
        self._page = self._browser.new_page()
        self._page.on("dialog", self._on_dialog)

    def _on_dialog(self, dialog) -> None:
        # An alert()/confirm()/prompt() firing is the money shot for XSS.
        self._dialogs.append(f"{dialog.type}: {dialog.message}")
        try:
            dialog.dismiss()
        except Exception:
            pass

    def stop(self) -> None:
        for closer in (self._browser, self._pw):
            try:
                if closer is self._pw and closer is not None:
                    closer.stop()
                elif closer is not None:
                    closer.close()
            except Exception:
                pass

    # dialogs ---------------------------------------------------------------
    def pop_dialog(self) -> Optional[str]:
        if self._dialogs:
            return self._dialogs.pop(0)
        return None

    def _drain_dialogs(self) -> Optional[str]:
        d = None
        while self._dialogs:
            d = self._dialogs.pop(0)
        return d

    # actions ---------------------------------------------------------------
    def _result(self) -> PageResult:
        return PageResult(
            url=self._page.url,
            html=self._page.content(),
            dialog=self._drain_dialogs(),
        )

    def probe_get(self, url: str, params: Dict[str, str]) -> PageResult:
        target = url
        if params:
            target = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
        self._page.goto(target, wait_until="load")
        self._page.wait_for_timeout(250)  # let onload handlers fire
        return self._result()

    def login(self, url, user_field, user, pass_field, password, submit=None, action_url=None) -> PageResult:
        # A real browser opens the login *page* and lets the form's own action
        # route the POST, so action_url is irrelevant here.
        self._page.goto(url, wait_until="load")
        self._page.fill(user_field, user)
        self._page.fill(pass_field, password)
        self._submit(submit, pass_field)
        return self._result()

    def submit_form(self, url, fields: Dict[str, str], submit=None, method="get") -> PageResult:
        self._page.goto(url, wait_until="load")
        last_selector = None
        for selector, value in fields.items():
            self._page.fill(selector, value)
            last_selector = selector
        self._submit(submit, last_selector)
        self._page.wait_for_timeout(250)
        return self._result()

    def _submit(self, submit: Optional[str], fallback_field: Optional[str]) -> None:
        try:
            if submit:
                self._page.click(submit)
            elif fallback_field:
                self._page.press(fallback_field, "Enter")
            self._page.wait_for_load_state("load")
        except Exception:
            # Navigation may have already happened or been blocked; ignore.
            pass

    def screenshot(self, path: str) -> Optional[str]:
        try:
            self._page.screenshot(path=path, full_page=True)
            return path
        except Exception:
            return None


# ---------------------------------------------------------------------------
# No-browser probe
# ---------------------------------------------------------------------------
class HttpProbe:
    kind = "http"
    can_prove_execution = False

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self._session = None

    def start(self) -> None:
        try:
            import requests
        except Exception as exc:  # pragma: no cover
            raise DriverError(
                "The 'requests' package is required for the http driver. "
                "Run scripts/install.sh."
            ) from exc
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "attack-loop/1.0 (authorized-test)"})

    def stop(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass

    def pop_dialog(self) -> Optional[str]:
        return None  # no JS engine -> no dialogs, ever

    def probe_get(self, url: str, params: Dict[str, str]) -> PageResult:
        try:
            r = self._session.get(url, params=params, timeout=self.timeout)
            return PageResult(url=r.url, status=r.status_code, html=r.text)
        except Exception as exc:
            return PageResult(url=url, error=f"{type(exc).__name__}: {exc}")

    def login(self, url, user_field, user, pass_field, password, submit=None, action_url=None) -> PageResult:
        # No DOM here, so we can't follow a <form action>. POST to the form's
        # action endpoint when the scenario tells us where it is.
        target = action_url or url
        data = {self._name(user_field): user, self._name(pass_field): password}
        try:
            r = self._session.post(target, data=data, timeout=self.timeout, allow_redirects=True)
            return PageResult(url=r.url, status=r.status_code, html=r.text)
        except Exception as exc:
            return PageResult(url=target, error=f"{type(exc).__name__}: {exc}")

    def submit_form(self, url, fields: Dict[str, str], submit=None, method="get") -> PageResult:
        data = {self._name(sel): val for sel, val in fields.items()}
        try:
            if method.lower() == "post":
                r = self._session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            else:
                r = self._session.get(url, params=data, timeout=self.timeout, allow_redirects=True)
            return PageResult(url=r.url, status=r.status_code, html=r.text)
        except Exception as exc:
            return PageResult(url=url, error=f"{type(exc).__name__}: {exc}")

    def screenshot(self, path: str) -> Optional[str]:
        return None

    @staticmethod
    def _name(selector: str) -> str:
        """Turn a CSS selector like input[name=q] into the field name 'q'.

        The HTTP probe speaks form-field names, not CSS, so we extract a best
        guess. A bare name is returned as-is.
        """
        import re

        m = re.search(r"name=['\"]?([^'\"\]]+)", selector)
        if m:
            return m.group(1)
        m = re.search(r"#([A-Za-z0-9_\-]+)", selector)
        if m:
            return m.group(1)
        return selector


def make_driver(name: str, headless: bool = False, slow_mo_ms: int = 350):
    name = (name or "").lower()
    if name in ("playwright", "browser", "chromium", "firefox", "webkit"):
        browser = name if name in ("chromium", "firefox", "webkit") else "chromium"
        return PlaywrightDriver(headless=headless, slow_mo_ms=slow_mo_ms, browser=browser)
    if name in ("http", "requests", "probe"):
        return HttpProbe()
    raise DriverError(f"Unknown driver {name!r}. Use 'playwright' or 'http'.")
