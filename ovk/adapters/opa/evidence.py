"""Normalize OPA raw results into OVK evidence."""

from __future__ import annotations

from typing import Any

from ovk.adapters.opa.self_protection import INTENT_ID, INTENT_TITLE
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


STATUS_MAP = {
    "pass": VerificationStatus.PASS,
    "fail": VerificationStatus.FAIL,
    "unknown": VerificationStatus.UNKNOWN,
    "error": VerificationStatus.ERROR,
    "skipped": VerificationStatus.SKIPPED,
}


def opa_raw_to_evidence(
    raw: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    actor_type: str = "unknown",
    agent: str = "unknown",
    task: str = "unknown",
) -> VerificationEvidence:
    """Convert optional OPA runner output into OVK evidence.

    This function is deliberately conservative. Unknown and error statuses remain
    unknown/error in the evidence object and never become pass.
    """
    raw_status = str(raw.get("status", "unknown"))
    status = STATUS_MAP.get(raw_status, VerificationStatus.UNKNOWN)

    if status == VerificationStatus.FAIL:
        recommendation = "block"
        human_review_required = True
    elif status in {VerificationStatus.UNKNOWN, VerificationStatus.ERROR, VerificationStatus.SKIPPED}:
        recommendation = "require_human_review"
        human_review_required = True
    else:
        recommendation = "allow"
        human_review_required = False

    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    violations = raw.get("violations", [])
    counterexamples = []
    if isinstance(violations, list):
        counterexamples = [
            {
                "summary": str(item),
                "failure_mode": "opa_policy_violation",
            }
            for item in violations
        ]

    reason = raw.get("reason")
    if not counterexamples and status in {VerificationStatus.UNKNOWN, VerificationStatus.ERROR}:
        counterexamples = [
            {
                "summary": str(reason or "OPA result did not establish a passing claim."),
                "failure_mode": "opa_unavailable_or_error",
            }
        ]

    return VerificationEvidence(
        evidence_id="ev-opa-self-protection",
        schema_version="ovk.evidence.v1",
        subject=subject,
        change_origin={
            "author_type": actor_type,
            "agent": agent,
            "task": task,
        },
        intent={
            "intent_id": INTENT_ID,
            "title": INTENT_TITLE,
            "risk": {"severity": "critical"},
        },
        backend_claims=[
            BackendClaim(
                backend="opa",
                guarantee_type="policy_evaluation",
                status=status,
                assumptions=[
                    "OPA evaluated the materialized self-protection policy when available.",
                    "Missing or unavailable OPA execution is represented as unknown or error.",
                ],
                limits=[
                    "OPA policy evaluation does not prove semantic correctness of workflow steps.",
                ],
                adapter_version="0.1.0",
            )
        ],
        counterexamples=counterexamples,
        generated_artifacts=[],
        decision={
            "merge_recommendation": recommendation,
            "human_review_required": human_review_required,
            "override_allowed": human_review_required,
            "override_requires": ["maintainer", "security-review"] if human_review_required else [],
        },
    )
