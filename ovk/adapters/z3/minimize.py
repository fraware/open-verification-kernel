"""Counterexample minimization stub for regression artifact generation."""

from __future__ import annotations

from typing import Any


ESSENTIAL_COUNTEREXAMPLE_KEYS = frozenset(
    {
        "summary",
        "failure_mode",
        "route",
        "user_role",
        "path",
        "obligation_id",
        "query_polarity",
        "principal",
        "gained_role",
        "roles_before",
        "roles_after",
        "affected_file",
        "line_hunk",
    }
)


def minimize_counterexample(counterexample: dict[str, Any]) -> dict[str, Any]:
    """Trim a counterexample to the smallest useful witness fields."""
    minimized = {
        key: value
        for key, value in counterexample.items()
        if key in ESSENTIAL_COUNTEREXAMPLE_KEYS and value is not None and value != [] and value != ""
    }
    if "summary" not in minimized and counterexample.get("summary"):
        minimized["summary"] = counterexample["summary"]
    minimized["minimized"] = True
    return minimized
