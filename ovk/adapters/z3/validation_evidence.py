"""Evidence helpers for invalid authorization abstractions."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.obligation import AuthorizationObligation, obligation_to_dict
from ovk.adapters.z3.validation import AuthorizationValidationIssue, issues_to_counterexamples
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def authorization_validation_to_evidence(
    issues: list[AuthorizationValidationIssue],
    obligation: AuthorizationObligation,
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    author_type: str = "unknown",
    agent: str = "unknown",
    task: str = "unknown",
) -> VerificationEvidence:
    """Build unknown evidence from invalid authorization input."""
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    return VerificationEvidence(
        evidence_id="ev-auth-obligation-validation",
        schema_version="ovk.evidence.v1",
        subject=subject,
        change_origin={
            "author_type": author_type,
            "agent": agent,
            "task": task,
        },
        intent={
            "intent_id": obligation.intent_id,
            "title": "No admin route bypass",
            "risk": {"severity": "high"},
        },
        backend_claims=[
            BackendClaim(
                backend="z3",
                guarantee_type="input_validation",
                status=VerificationStatus.UNKNOWN,
                assumptions=obligation.assumptions,
                limits=[
                    "Authorization route abstraction failed validation.",
                    "Invalid input cannot support a passing claim.",
                ],
                adapter_version="0.3.0",
            )
        ],
        counterexamples=issues_to_counterexamples(issues),
        generated_artifacts=[
            {
                "kind": "authorization_obligation",
                "obligation": obligation_to_dict(obligation),
            }
        ],
        decision={
            "merge_recommendation": "require_human_review",
            "human_review_required": True,
            "override_allowed": True,
            "override_requires": ["maintainer", "security-review"],
        },
    )
