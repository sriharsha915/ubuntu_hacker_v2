"""Scenario registry.

Add a scenario by importing its class and dropping it in SCENARIOS. The CLI,
the report, and the strategists all discover scenarios through here.
"""

from __future__ import annotations

from typing import Dict, List, Type

from .base import Scenario
from .reflected_xss import ReflectedXssScenario
from .sqli_login import SqliLoginScenario

SCENARIOS: Dict[str, Type[Scenario]] = {
    ReflectedXssScenario.kind: ReflectedXssScenario,
    SqliLoginScenario.kind: SqliLoginScenario,
}


def available() -> List[str]:
    return sorted(SCENARIOS)


def build_scenario(kind: str, base_url: str, **overrides) -> Scenario:
    if kind not in SCENARIOS:
        raise KeyError(
            f"Unknown scenario {kind!r}. Available: {', '.join(available())}"
        )
    # Drop None overrides so scenario DEFAULTS win where the CLI passed nothing.
    clean = {k: v for k, v in overrides.items() if v is not None}
    return SCENARIOS[kind](base_url, **clean)


__all__ = ["Scenario", "SCENARIOS", "available", "build_scenario"]
