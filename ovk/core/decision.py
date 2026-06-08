"""Merge decision logic for OVK evidence bundles."""

from __future__ import annotations

from ovk.core.models import EvidenceBundle, MergeRecommendation, VerificationStatus


CRITICAL = "critical"


def evidence_has_status(bundle: EvidenceBundle, status: VerificationStatus) -> bool:
    """Return true if any backend claim in the bundle has the given status."""
    return any(
        claim.status == status
        for evidence in bundle.evidence
        for claim in evidence.backend_claims
    )


def evidence_has_unknown_like(bundle: EvidenceBundle) -> bool:
    """Unknown-like outcomes must never be treated as pass in enforce mode."""
    unknown_like = {
        VerificationStatus.UNKNOWN,
        VerificationStatus.ERROR,
        VerificationStatus.SKIPPED,
    }
    return any(
        claim.status in unknown_like
        for evidence in bundle.evidence
        for claim in evidence.backend_claims
    )


def has_critical_intent(bundle: EvidenceBundle) -> bool:
    """Best-effort critical-risk detector for starter implementation."""
    return any(
        evidence.intent.get("risk", {}).get("severity") == CRITICAL
        or evidence.intent.get("severity") == CRITICAL
        for evidence in bundle.evidence
    )


def decide(bundle: EvidenceBundle, enforce: bool = True) -> MergeRecommendation:
    """Compute a conservative merge recommendation.

    Critical failures block. Unknown-like critical results require human review.
    In enforce mode, any failure blocks by default until risk-aware policies are implemented.
    """
    if evidence_has_status(bundle, VerificationStatus.FAIL):
        return MergeRecommendation.BLOCK if enforce else MergeRecommendation.ALLOW_WITH_WARNING

    if evidence_has_unknown_like(bundle):
        return MergeRecommendation.REQUIRE_HUMAN_REVIEW if enforce else MergeRecommendation.ALLOW_WITH_WARNING

    return MergeRecommendation.ALLOW
