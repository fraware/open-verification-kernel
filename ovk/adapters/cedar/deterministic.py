"""Deterministic Cedar/IAM policy oracle for CI without the Cedar binary."""

from __future__ import annotations

from typing import Any


def evaluate_cedar_input(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate Cedar-shaped IAM policy input with a conservative oracle."""
    if data.get("malformed"):
        return "unknown", [{"summary": "Malformed Cedar/IAM input.", "failure_mode": "malformed_input"}]

    violations = list(data.get("violations", []))
    policies = data.get("policies", [])
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        principal = str(policy.get("principal", ""))
        action = str(policy.get("action", ""))
        effect = str(policy.get("effect", "")).lower()
        if effect == "allow" and principal in {"*", "anonymous"} and "admin" in action.lower():
            violations.append("admin action permitted for unauthenticated principal")

    if violations:
        return "fail", [{"summary": str(violations[0]), "failure_mode": "policy_violation"}]
    return "pass", []
