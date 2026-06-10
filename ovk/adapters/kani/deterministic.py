"""Deterministic Rust safety oracle used when Kani is unavailable."""

from __future__ import annotations

from typing import Any


def evaluate_kani_input(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate Rust harness input with a conservative safety oracle."""
    if data.get("malformed"):
        return "unknown", [{"summary": "Malformed Rust harness input.", "failure_mode": "malformed_input"}]

    violations = [str(item) for item in data.get("violations", [])]
    unsafe_ops = data.get("unsafe_operations", [])
    if unsafe_ops:
        violations.extend(str(item) for item in unsafe_ops)

    findings = data.get("findings", [])
    for finding in findings:
        if isinstance(finding, dict) and finding.get("kind") == "memory_safety":
            violations.append(str(finding.get("summary", "memory safety violation")))

    if violations:
        failure_mode = "memory_safety_violation" if unsafe_ops or findings else "policy_violation"
        return "fail", [{"summary": str(violations[0]), "failure_mode": failure_mode}]
    return "pass", []
