"""Evidence for compilation and planning failures."""

from __future__ import annotations

from typing import Any

from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def compilation_failure_evidence(
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    intents: list[str],
    reason: str,
) -> VerificationEvidence:
    """Return conservative evidence when lane input compilation cannot proceed."""
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha
    return VerificationEvidence(
        evidence_id="ev-compilation-failure",
        subject=subject,
        intent={
            "intent_id": "compilation-incomplete",
            "title": "Lane input compilation incomplete",
            "risk": {"severity": "high"},
        },
        backend_claims=[
            BackendClaim(
                backend="ovk",
                guarantee_type="compilation",
                status=VerificationStatus.UNKNOWN,
                assumptions=["Compilation failure must not downgrade to allow."],
                limits=["No lane evaluator ran because required inputs could not be compiled."],
                adapter_version="1.0.0",
            )
        ],
        decision={"merge_recommendation": "require_human_review", "human_review_required": True},
        counterexamples=[
            {
                "summary": reason,
                "failure_mode": "compilation_incomplete",
                "candidate_intents": intents,
            }
        ],
    )
