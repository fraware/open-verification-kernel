"""Merge decision logic for OVK evidence bundles."""

from __future__ import annotations

from ovk.core.models import EvidenceBundle, MergeRecommendation, VerificationStatus


def evidence_has_status(bundle: EvidenceBundle, status: VerificationStatus) -> bool:
    """Return true if any backend claim in the bundle has the given status."""
    return any(claim.status == status for evidence in bundle.evidence for claim in evidence.backend_claims)


def evidence_has_unknown_like(bundle: EvidenceBundle) -> bool:
    """Unknown-like outcomes must never be treated as pass in enforce mode."""
    unknown_like = {
        VerificationStatus.UNKNOWN,
        VerificationStatus.ERROR,
        VerificationStatus.SKIPPED,
    }
    return any(claim.status in unknown_like for evidence in bundle.evidence for claim in evidence.backend_claims)


def _unknown_like_recommendation(
    *,
    enforce: bool,
    default_on_unknown: str,
) -> MergeRecommendation:
    if not enforce:
        return MergeRecommendation.ALLOW_WITH_WARNING
    if default_on_unknown == "block":
        return MergeRecommendation.BLOCK
    if default_on_unknown == "allow_with_warning":
        return MergeRecommendation.ALLOW_WITH_WARNING
    return MergeRecommendation.REQUIRE_HUMAN_REVIEW


def _decision_reason(recommendation: MergeRecommendation, *, from_unknown: bool = False) -> str:
    if recommendation == MergeRecommendation.BLOCK:
        if from_unknown:
            return "one or more verification intents returned an unknown-like result"
        return "one or more verification intents failed"
    if recommendation in {
        MergeRecommendation.REQUIRE_HUMAN_REVIEW,
        MergeRecommendation.REQUIRE_STRONGER_CHECK,
    }:
        return "one or more verification intents returned an unknown-like result"
    if recommendation == MergeRecommendation.ALLOW_WITH_WARNING:
        return "verification completed with warnings in advisory mode"
    return "all evaluated verification intents passed"


def decide(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
) -> MergeRecommendation:
    """Compute a conservative merge recommendation.

    Critical failures block. Unknown-like outcomes follow ``default_on_unknown`` when
    ``enforce`` is true (from ``.verification/config.yml`` in the kernel path).
    """
    if evidence_has_status(bundle, VerificationStatus.FAIL):
        return MergeRecommendation.BLOCK if enforce else MergeRecommendation.ALLOW_WITH_WARNING

    if evidence_has_unknown_like(bundle):
        skipped_only = all(
            claim.status in {VerificationStatus.SKIPPED, VerificationStatus.PASS}
            for evidence in bundle.evidence
            for claim in evidence.backend_claims
        ) and evidence_has_status(bundle, VerificationStatus.SKIPPED)
        if skipped_only and not enforce:
            return MergeRecommendation.ALLOW_WITH_WARNING
        return _unknown_like_recommendation(enforce=enforce, default_on_unknown=default_on_unknown)

    return MergeRecommendation.ALLOW


def decide_with_reason(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
) -> dict[str, str]:
    """Return merge recommendation and human-readable reason for bundle construction."""
    recommendation = decide(bundle, enforce=enforce, default_on_unknown=default_on_unknown)
    from_unknown = (
        recommendation
        in {
            MergeRecommendation.BLOCK,
            MergeRecommendation.REQUIRE_HUMAN_REVIEW,
            MergeRecommendation.ALLOW_WITH_WARNING,
        }
        and evidence_has_unknown_like(bundle)
        and not evidence_has_status(bundle, VerificationStatus.FAIL)
    )
    return {
        "merge_recommendation": recommendation.value,
        "reason": _decision_reason(recommendation, from_unknown=from_unknown),
    }
