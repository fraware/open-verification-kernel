"""Exit-code helpers for OVK runner recommendations."""

from __future__ import annotations


RECOMMENDATION_EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


def exit_code_for_recommendation(recommendation: str) -> int:
    """Return the process exit code for a merge recommendation."""
    return RECOMMENDATION_EXIT_CODES.get(recommendation, 2)
