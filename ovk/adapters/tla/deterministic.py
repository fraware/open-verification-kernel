"""Deterministic TLA+/deployment state-machine oracle."""

from __future__ import annotations

from typing import Any


def evaluate_tla_input(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate deployment state-machine input with a bounded oracle."""
    if data.get("malformed"):
        return "unknown", [{"summary": "Malformed state machine.", "failure_mode": "malformed_state_machine"}]
    if data.get("skipped_states"):
        return "fail", [
            {
                "summary": "Skipped approval state detected.",
                "failure_mode": "required_approval_state_skipped",
            }
        ]
    required = data.get("required_approval_states", [])
    states = data.get("states", [])
    if required and states:
        present = {str(state.get("name")) for state in states if isinstance(state, dict)}
        missing = [name for name in required if name not in present]
        if missing:
            return "fail", [
                {
                    "summary": f"Missing required approval states: {', '.join(missing)}",
                    "failure_mode": "required_approval_state_skipped",
                }
            ]
    return "pass", []
