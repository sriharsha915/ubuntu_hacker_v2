"""Scenario base class.

A Strategist is the brain (*what* to try). A Scenario is the hands (*how* to
apply one attempt to this particular target and *how* to recognise a win).
Keeping them separate means the same brain drives any scenario, and the same
scenario works under any brain or driver.
"""

from __future__ import annotations

import html as _html
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

from core.models import Objective, Observation, Payload


class Scenario:
    kind = "generic"

    def __init__(self, base_url: str, **params):
        self.base_url = base_url.rstrip("/") + "/"
        self.params = params

    # --- metadata the loop/report use -------------------------------------
    @property
    def name(self) -> str:
        return self.params.get("name", self.kind)

    @property
    def component(self) -> str:
        return self.params.get("component", self.kind)

    @property
    def target_url(self) -> str:
        return self.base_url

    def objective(self) -> Objective:
        return Objective(
            name=self.name,
            kind=self.kind,
            target_url=self.target_url,
            component=self.component,
            params=dict(self.params),
            success_criteria=self.signal_description(),
        )

    def signal_description(self) -> str:
        return "a technique-specific success condition is met"

    # --- lifecycle --------------------------------------------------------
    def preflight(self, driver, console) -> None:
        """Set the target up (navigate, authenticate) before the loop fires."""

    def candidate_payloads(self) -> List[Payload]:
        raise NotImplementedError

    def attempt(self, driver, console, payload: Payload) -> Observation:
        raise NotImplementedError

    # --- shared helpers ---------------------------------------------------
    def url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    @staticmethod
    def _looks_too_long(result) -> Optional[str]:
        """Return an error message if the target rejected input for length.

        Prefers a message that actually states the limit (e.g. "max 30
        characters") over an incidental match like a page's <title>, so the
        strategist can parse the cap and shorten intelligently.
        """
        text = (result.html or "")
        trigger = re.search(r"too long|max(?:imum)?\s+\d+\s*char|length limit", text, re.I)
        if result.status != 400 and not trigger:
            return None
        candidates = re.findall(
            r"[^<>\n]*(?:too long|max[^<>\n]{0,40}char|length limit)[^<>\n]*", text, re.I
        )
        candidates = [c.strip() for c in candidates if c.strip()]
        if candidates:
            with_num = [c for c in candidates if re.search(r"\d", c)]
            pool = with_num or candidates
            return max(pool, key=len)       # the most specific message available
        return "input rejected (too long)"

    @staticmethod
    def _reflected_unescaped(payload: str, html_text: str) -> bool:
        """True if the raw payload appears in the response without HTML-encoding.

        Deliberately conservative: we require the *whole* raw payload to be
        present verbatim. A looser "does the opening <tag appear" check caused
        false positives (``<b`` matches ``<body>`` on an unrelated page), which
        would wrongly flag a safe component as vulnerable.
        """
        if not payload or not html_text:
            return False
        if _html.escape(payload) in html_text and payload not in html_text:
            return False                  # present only in neutralised form -> safe
        return payload in html_text       # raw, unescaped -> dangerous
