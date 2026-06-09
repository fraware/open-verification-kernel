"""Deterministic validated authorization path.

This path preserves the stable adapter contract without requiring z3-solver. It
validates the route abstraction, builds an obligation, and uses deterministic
witness translation to produce OVK evidence.
"""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.counterexample import counterexamples_from_obligation
from ovk.adapters.z3.evidence import authorization_result_to_evidence
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.validation import validate_authorization_input
from ovk.adapters.z3.validation_evidence import authorization_validation_to_evidence
from ovk.core.models import VerificationEvidence


def evaluate_deterministic_authorization_path(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate authorization without requiring an external SMT solver."""
    obligation = build_authorization_obligation(data)
    author_type = str(data.get("author_type", "unknown"))
    agent = str(data.get("agent", "unknown"))
    task = str(data.get("task", "unknown"))
    issues = validate_authorization_input(data)
    if issues:
        return authorization_validation_to_evidence(
            issues,
            obligation,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            author_type=author_type,
            agent=agent,
            task=task,
        )

    counterexamples = counterexamples_from_obligation(obligation)
    models = [
        {
            "route": item.get("route"),
            "user_role": item.get("user_role"),
            "path": item.get("path", []),
            "model": "deterministic_witness",
            "obligation_id": item.get("obligation_id"),
            "query_polarity": item.get("query_polarity"),
        }
        for item in counterexamples
    ]
    raw = {
        "status": "fail" if models else "pass",
        "reason": "deterministic violation witness found" if models else "no deterministic violation witness found",
        "models": models,
    }
    return authorization_result_to_evidence(
        raw,
        obligation,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        author_type=author_type,
        agent=agent,
        task=task,
    )
