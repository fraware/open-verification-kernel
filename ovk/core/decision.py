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


def _decision_reason(recommendation: MergeRecommendation) -> str:
    if recommendation == MergeRecommendation.BLOCK:
        return "one or more verification intents failed"
    if recommendation in {
        MergeRecommendation.REQUIRE_HUMAN_REVIEW,
        MergeRecommendation.REQUIRE_STRONGER_CHECK,
    }:
        return "one or more verification intents returned an unknown-like result"
    if recommendation == MergeRecommendation.ALLOW_WITH_WARNING:
        return "verification completed with warnings in advisory mode"
    return "all evaluated verification intents passed"


def decide(bundle: EvidenceBundle, enforce: bool = True) -> MergeRecommendation:
    """Compute a conservative merge recommendation.

    Critical failures block. Unknown-like critical results require human review.
    In enforce mode, any failure blocks by default until risk-aware policies are implemented.
    """
    if evidence_has_status(bundle, VerificationStatus.FAIL):
        return MergeRecommendation.BLOCK if enforce else MergeRecommendation.ALLOW_WITH_WARNING

    if evidence_has_unknown_like(bundle):
        if has_critical_intent(bundle):
            return MergeRecommendation.REQUIRE_HUMAN_REVIEW if enforce else MergeRecommendation.ALLOW_WITH_WARNING
        skipped_only = all(
            claim.status in {VerificationStatus.SKIPPED, VerificationStatus.PASS}
            for evidence in bundle.evidence
            for claim in evidence.backend_claims
        ) and evidence_has_status(bundle, VerificationStatus.SKIPPED)
        if skipped_only and not enforce:
            return MergeRecommendation.ALLOW_WITH_WARNING
        return MergeRecommendation.REQUIRE_HUMAN_REVIEW if enforce else MergeRecommendation.ALLOW_WITH_WARNING

    return MergeRecommendation.ALLOW


def decide_with_reason(bundle: EvidenceBundle, enforce: bool = True) -> dict[str, str]:
    """Return merge recommendation and human-readable reason for bundle construction."""
    recommendation = decide(bundle, enforce=enforce)
    return {
        "merge_recommendation": recommendation.value,
        "reason": _decision_reason(recommendation),
    }
