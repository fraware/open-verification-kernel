"""Shared deterministic oracles for wave-2 proof and model-checking backends."""

from __future__ import annotations

from typing import Any


def evaluate_proof_obligation(
    data: dict[str, Any],
    *,
    failure_mode: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate proof-assistant shaped input with a conservative oracle."""
    if data.get("malformed"):
        return "unknown", [{"summary": "Malformed proof obligation input.", "failure_mode": "malformed_input"}]

    violations = [str(item) for item in data.get("violations", [])]
    unproved = data.get("unproved_obligations", [])
    if unproved:
        violations.extend(str(item) for item in unproved)

    if violations:
        return "fail", [{"summary": str(violations[0]), "failure_mode": failure_mode}]
    return "pass", []


def evaluate_bounded_model(
    data: dict[str, Any],
    *,
    failure_mode: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate bounded model-checking shaped input with a conservative oracle."""
    if data.get("malformed"):
        return "unknown", [{"summary": "Malformed model-checking input.", "failure_mode": "malformed_input"}]

    violations = [str(item) for item in data.get("violations", [])]
    failed_assertions = data.get("failed_assertions", [])
    if failed_assertions:
        violations.extend(str(item) for item in failed_assertions)

    counterexamples = data.get("counterexample_instances", [])
    if counterexamples:
        violations.extend(str(item) for item in counterexamples)

    if violations:
        return "fail", [{"summary": str(violations[0]), "failure_mode": failure_mode}]
    return "pass", []
