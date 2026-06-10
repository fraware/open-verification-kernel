"""Factory helpers for optional external backend evaluators."""

from __future__ import annotations

from typing import Any, Callable

from ovk.adapters.external.stub import evaluate_with_optional_binary


def _policy_pass(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    violations = data.get("violations", [])
    if violations:
        return "fail", [{"summary": str(violations[0]), "failure_mode": "policy_violation"}]
    if data.get("malformed"):
        return "unknown", [{"summary": "malformed input", "failure_mode": "malformed_input"}]
    return "pass", []


def make_backend_evaluator(
    *,
    backend_name: str,
    binary_name: str,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    data: dict[str, Any],
    deterministic_evaluator: Callable[[dict[str, Any]], tuple[str, list[dict[str, Any]]]] | None = None,
):
    """Build a VerificationEvidence for an external backend."""
    evaluator = deterministic_evaluator or _policy_pass
    return evaluate_with_optional_binary(
        backend_name=backend_name,
        binary_name=binary_name,
        data=data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        deterministic_evaluator=evaluator,
        assumptions=[f"{backend_name} adapter uses deterministic fallback when binary is absent."],
        limits=[f"{backend_name} does not prove unbounded properties without the native tool."],
    )
