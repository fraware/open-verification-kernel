"""Z3-style authorization reachability adapter.

This stable adapter uses the deterministic validated authorization path. It
preserves the original no-external-solver contract while ensuring invalid route
abstractions return unknown and require human review.
"""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.counterexample import counterexamples_from_obligation
from ovk.adapters.z3.deterministic_path import evaluate_deterministic_authorization_path
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.core.models import VerificationEvidence


INTENT_ID = "no-admin-route-bypass"
INTENT_TITLE = "No admin route bypass"


def find_authorization_counterexamples(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Find authorization counterexamples through the obligation model."""
    obligation = build_authorization_obligation(data)
    return counterexamples_from_obligation(obligation)


def evaluate_authorization_reachability(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    pull_request: int | str | None = None,
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate authorization reachability and return normalized OVK evidence."""
    evidence = evaluate_deterministic_authorization_path(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    if pull_request is not None:
        evidence.subject["pull_request"] = pull_request
    return evidence
