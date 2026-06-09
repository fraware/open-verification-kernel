"""Validated authorization obligation path."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.evidence import authorization_result_to_evidence
from ovk.adapters.z3.executor import run_authorization_obligation_with_z3
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.validation import validate_authorization_input
from ovk.adapters.z3.validation_evidence import authorization_validation_to_evidence
from ovk.core.models import VerificationEvidence


def evaluate_validated_authorization_path(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Validate input, run optional Z3 when valid, and return OVK evidence."""
    obligation = build_authorization_obligation(data)
    issues = validate_authorization_input(data)
    author_type = str(data.get("author_type", "unknown"))
    agent = str(data.get("agent", "unknown"))
    task = str(data.get("task", "unknown"))

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

    raw = run_authorization_obligation_with_z3(obligation)
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
