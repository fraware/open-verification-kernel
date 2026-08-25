"""Exit-code helpers for OVK runner recommendations."""

from __future__ import annotations

from ovk.core.decision import merge_recommendation_to_decision_state
from ovk.core.models import DecisionState

# Normative lattice → process exit code.
DECISION_STATE_EXIT_CODES = {
    DecisionState.ALLOW.value: 0,
    DecisionState.BLOCK.value: 1,
    DecisionState.NEEDS_REVIEW.value: 2,
    DecisionState.UNKNOWN.value: 2,
    DecisionState.ERROR.value: 2,
    DecisionState.SKIPPED.value: 2,
}

# Deprecated merge_recommendation aliases (including non-lattice legacy values).
RECOMMENDATION_EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
    "needs_review": 2,
    "unknown": 2,
    "error": 2,
    "skipped": 2,
}


def exit_code_for_decision_state(decision_state: str | DecisionState) -> int:
    """Return the process exit code for a normative ``DecisionState``."""
    if isinstance(decision_state, DecisionState):
        key = decision_state.value
    else:
        key = str(decision_state).strip()
    if key in DECISION_STATE_EXIT_CODES:
        return DECISION_STATE_EXIT_CODES[key]
    # Accept legacy aliases by mapping onto the lattice first.
    mapped = merge_recommendation_to_decision_state(key)
    return DECISION_STATE_EXIT_CODES.get(mapped.value, 2)


def exit_code_for_recommendation(recommendation: str) -> int:
    """Return the process exit code for a merge recommendation or decision_state.

    Prefers ``decision_state`` semantics when the value is a lattice member;
    falls back to legacy ``merge_recommendation`` aliases.
    """
    if recommendation in DECISION_STATE_EXIT_CODES:
        return DECISION_STATE_EXIT_CODES[recommendation]
    return RECOMMENDATION_EXIT_CODES.get(recommendation, 2)
