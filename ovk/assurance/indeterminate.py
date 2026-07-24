"""Map terminations and exit kinds to typed indeterminate decisions.

Timeouts, missing checkers, and related failures MUST NEVER map to accept.
"""

from __future__ import annotations

from typing import Any

# PCS VerificationResult.v1 decision vocabulary
DECISION_ACCEPT = "accept"
DECISION_REJECT = "reject"
DECISION_INDETERMINATE_INSUFFICIENT = "indeterminate_insufficient_evidence"
DECISION_INDETERMINATE_EXECUTION = "indeterminate_execution_error"
DECISION_INDETERMINATE_OUT_OF_SCOPE = "indeterminate_out_of_scope"
DECISION_INDETERMINATE_DRIFT = "indeterminate_configuration_drift"

# PCS indeterminate_reason vocabulary
REASON_MISSING_CHECKER = "missing_checker"
REASON_TIMEOUT = "timeout"
REASON_PARSER_FAILURE = "parser_failure"
REASON_UNSUPPORTED_INPUT = "unsupported_input"
REASON_EXTERNAL_SERVICE = "external_service_error"
REASON_RESOURCE_EXHAUSTED = "resource_exhausted"
REASON_SPAWN_ERROR = "spawn_error"
REASON_INCOMPLETE_TRAJECTORY = "incomplete_trajectory"
REASON_MISSING_AUTH_STATE = "missing_authoritative_state"
REASON_DECLARED_NONDETERMINISM = "declared_nondeterminism"
REASON_OTHER = "other"

_TERMINATION_TO_REASON: dict[str, str] = {
    "timeout": REASON_TIMEOUT,
    "resource_exhausted": REASON_RESOURCE_EXHAUSTED,
    "tool_unavailable": REASON_MISSING_CHECKER,
    "tool_error": REASON_OTHER,
    "invalid_output": REASON_PARSER_FAILURE,
    "cancelled": REASON_OTHER,
    "missing_checker": REASON_MISSING_CHECKER,
    "spawn_error": REASON_SPAWN_ERROR,
    "parser_failure": REASON_PARSER_FAILURE,
    "unsupported_input": REASON_UNSUPPORTED_INPUT,
    "external_service_error": REASON_EXTERNAL_SERVICE,
}

_REASON_TO_DECISION: dict[str, str] = {
    REASON_MISSING_CHECKER: DECISION_INDETERMINATE_EXECUTION,
    REASON_TIMEOUT: DECISION_INDETERMINATE_EXECUTION,
    REASON_PARSER_FAILURE: DECISION_INDETERMINATE_EXECUTION,
    REASON_UNSUPPORTED_INPUT: DECISION_INDETERMINATE_OUT_OF_SCOPE,
    REASON_EXTERNAL_SERVICE: DECISION_INDETERMINATE_EXECUTION,
    REASON_RESOURCE_EXHAUSTED: DECISION_INDETERMINATE_EXECUTION,
    REASON_SPAWN_ERROR: DECISION_INDETERMINATE_EXECUTION,
    REASON_INCOMPLETE_TRAJECTORY: DECISION_INDETERMINATE_INSUFFICIENT,
    REASON_MISSING_AUTH_STATE: DECISION_INDETERMINATE_INSUFFICIENT,
    REASON_DECLARED_NONDETERMINISM: DECISION_INDETERMINATE_INSUFFICIENT,
    REASON_OTHER: DECISION_INDETERMINATE_EXECUTION,
}

_REASON_TO_EXECUTION_STATUS: dict[str, str] = {
    REASON_MISSING_CHECKER: "unavailable",
    REASON_TIMEOUT: "timeout",
    REASON_PARSER_FAILURE: "error",
    REASON_UNSUPPORTED_INPUT: "completed",
    REASON_EXTERNAL_SERVICE: "error",
    REASON_RESOURCE_EXHAUSTED: "resource_exhausted",
    REASON_SPAWN_ERROR: "error",
    REASON_INCOMPLETE_TRAJECTORY: "completed",
    REASON_MISSING_AUTH_STATE: "completed",
    REASON_DECLARED_NONDETERMINISM: "completed",
    REASON_OTHER: "error",
}


def indeterminate_reason_for_termination(termination: str) -> str:
    """Map a termination / exit kind to a typed indeterminate reason."""
    key = str(termination or "").strip().lower()
    return _TERMINATION_TO_REASON.get(key, REASON_OTHER)


def decision_for_indeterminate_reason(reason: str) -> str:
    """Map an indeterminate reason to a VerificationResult.v1 decision."""
    decision = _REASON_TO_DECISION.get(reason, DECISION_INDETERMINATE_EXECUTION)
    if decision in {DECISION_ACCEPT, DECISION_REJECT}:
        # Hard invariant: never upgrade failure to accept/reject here.
        return DECISION_INDETERMINATE_EXECUTION
    return decision


def execution_status_for_reason(reason: str) -> str:
    """Map an indeterminate reason to an execution_status value."""
    return _REASON_TO_EXECUTION_STATUS.get(reason, "tool_error")


def indeterminate_outcome(
    *,
    termination: str | None = None,
    reason: str | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    """Build a typed indeterminate outcome dict (never accept)."""
    resolved_reason = reason or indeterminate_reason_for_termination(termination or REASON_OTHER)
    decision = decision_for_indeterminate_reason(resolved_reason)
    if decision == DECISION_ACCEPT:
        raise RuntimeError("indeterminate_outcome must never produce accept")
    return {
        "decision": decision,
        "execution_status": execution_status_for_reason(resolved_reason),
        "indeterminate_reason": resolved_reason,
        "message": message,
    }
