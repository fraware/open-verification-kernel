"""Shared deterministic oracles for wave-2 proof and model-checking backends."""

from __future__ import annotations

from typing import Any


def classify_conformance_flags(
    data: dict[str, Any],
) -> tuple[str, list[dict[str, Any]]] | None:
    """Return an early outcome for shared conformance fixture flags, else None.

    Recognized flags (checked in order):
    - ``malformed`` → unknown / malformed_input
    - ``timeout`` → unknown / timeout
    - ``binary_unavailable`` or ``unavailable`` → unknown / binary_unavailable
    """
    if data.get("malformed"):
        return "unknown", [
            {"summary": "Malformed input.", "failure_mode": "malformed_input"}
        ]
    if data.get("timeout"):
        return "unknown", [
            {"summary": "Checker timed out within the declared budget.", "failure_mode": "timeout"}
        ]
    if data.get("binary_unavailable") or data.get("unavailable"):
        return "unknown", [
            {
                "summary": "Required checker binary is unavailable.",
                "failure_mode": "binary_unavailable",
            }
        ]
    return None


def evaluate_proof_obligation(
    data: dict[str, Any],
    *,
    failure_mode: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate proof-assistant shaped input with a conservative oracle."""
    early = classify_conformance_flags(data)
    if early is not None:
        return early

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
    early = classify_conformance_flags(data)
    if early is not None:
        return early

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
