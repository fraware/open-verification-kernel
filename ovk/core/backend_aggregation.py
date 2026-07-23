"""Backend result aggregation policies.

Versioned policy: ``ovk.aggregate.fail_dominant.v1``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from ovk.core.execution_models import BackendSelection, NormalizedBackendResult
from ovk.core.models import MergeRecommendation, VerificationStatus

AGGREGATION_FAIL_DOMINANT_V1 = "ovk.aggregate.fail_dominant.v1"


@dataclass(frozen=True)
class AggregationOutcome:
    """Result of aggregating required and optional backend results."""

    status: VerificationStatus
    merge_recommendation: MergeRecommendation
    reason: str
    disagreement: dict[str, Any] | None = None
    warnings: tuple[str, ...] = ()
    quality_error: bool = False


def build_disagreement_artifact(
    *,
    obligation_id: str,
    results: Sequence[NormalizedBackendResult],
    resolution: str,
    policy: str = AGGREGATION_FAIL_DOMINANT_V1,
) -> dict[str, Any]:
    """Create an explicit backend disagreement artifact."""
    return {
        "kind": "backend_disagreement",
        "obligation_id": obligation_id,
        "results": [
            {"backend": item.backend, "status": item.status.value}
            for item in sorted(results, key=lambda row: row.backend)
        ],
        "resolution": resolution,
        "policy": policy,
    }


def _statuses_by_backend(
    results: Sequence[NormalizedBackendResult],
) -> dict[str, VerificationStatus]:
    return {item.backend: item.status for item in results}


def aggregate_fail_dominant_v1(
    *,
    obligation_id: str,
    selected: Sequence[BackendSelection],
    results: Sequence[NormalizedBackendResult],
    acceptable_guarantees: Sequence[str] | None = None,
    fallback_accepted: bool = False,
) -> AggregationOutcome:
    """Apply the fail-dominant aggregation decision table.

    Decision table (required backends):
    * any fail -> block
    * no fail, any error/timeout/unknown/skipped -> require_human_review
    * every required pass with acceptable guarantees -> allow
    * no required result -> require_human_review
    * selected vs executed mismatch -> require_human_review + quality error
    * unaccepted weaker fallback -> require_stronger_check

    Optional corroborators:
    * optional fail upgrades to block
    * optional unknown/error warns without invalidating required pass
    * optional pass cannot upgrade required unknown
    """
    selected_required = [item for item in selected if item.required]
    selected_optional = [item for item in selected if not item.required]
    by_backend = _statuses_by_backend(results)
    executed = set(by_backend)
    selected_ids = {item.backend for item in selected}

    if selected_ids != executed:
        missing = sorted(selected_ids - executed)
        unexpected = sorted(executed - selected_ids)
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            merge_recommendation=MergeRecommendation.REQUIRE_HUMAN_REVIEW,
            reason=(
                "selected and executed backend sets differ; "
                f"missing={missing}; unexpected={unexpected}"
            ),
            quality_error=True,
        )

    required_results = [item for item in results if item.backend in {s.backend for s in selected_required}]
    optional_results = [item for item in results if item.backend in {s.backend for s in selected_optional}]

    if selected_required and not required_results:
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            merge_recommendation=MergeRecommendation.REQUIRE_HUMAN_REVIEW,
            reason="no required result exists",
            quality_error=True,
        )

    warnings: list[str] = []
    disagreement = None

    # Optional fail upgrades aggregate to block.
    if any(item.status == VerificationStatus.FAIL for item in optional_results):
        if required_results and any(item.status == VerificationStatus.PASS for item in required_results):
            disagreement = build_disagreement_artifact(
                obligation_id=obligation_id,
                results=list(results),
                resolution="block",
            )
        return AggregationOutcome(
            status=VerificationStatus.FAIL,
            merge_recommendation=MergeRecommendation.BLOCK,
            reason="optional corroborator reported fail",
            disagreement=disagreement,
        )

    if any(item.status == VerificationStatus.FAIL for item in required_results):
        if len({item.status for item in required_results}) > 1 or optional_results:
            disagreement = build_disagreement_artifact(
                obligation_id=obligation_id,
                results=list(results),
                resolution="block",
            )
        return AggregationOutcome(
            status=VerificationStatus.FAIL,
            merge_recommendation=MergeRecommendation.BLOCK,
            reason="required backend reported fail",
            disagreement=disagreement,
        )

    non_pass = {
        VerificationStatus.ERROR,
        VerificationStatus.UNKNOWN,
        VerificationStatus.SKIPPED,
    }
    if any(item.status in non_pass for item in required_results):
        for item in optional_results:
            if item.status == VerificationStatus.PASS:
                warnings.append(
                    f"optional backend {item.backend} passed but cannot upgrade required unknown/error"
                )
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            merge_recommendation=MergeRecommendation.REQUIRE_HUMAN_REVIEW,
            reason="required backend reported unknown, error, or skipped",
            warnings=tuple(warnings),
        )

    if not required_results and not selected_required:
        # No required selection — conservative review.
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            merge_recommendation=MergeRecommendation.REQUIRE_HUMAN_REVIEW,
            reason="no required backends were selected",
        )

    # Check guarantees / fallback acceptance for required passes.
    acceptable = set(acceptable_guarantees or [])
    for item in required_results:
        if acceptable and item.guarantee_type not in acceptable and not fallback_accepted:
            return AggregationOutcome(
                status=VerificationStatus.UNKNOWN,
                merge_recommendation=MergeRecommendation.REQUIRE_STRONGER_CHECK,
                reason=(
                    f"required result from {item.backend} uses guarantee "
                    f"{item.guarantee_type!r} outside acceptable set"
                ),
            )

    for item in optional_results:
        if item.status in non_pass:
            warnings.append(f"optional backend {item.backend} returned {item.status.value}")

    return AggregationOutcome(
        status=VerificationStatus.PASS,
        merge_recommendation=MergeRecommendation.ALLOW,
        reason="every required backend passed with acceptable guarantees",
        warnings=tuple(warnings),
    )


def aggregate_results(
    *,
    obligation_id: str,
    selected: Sequence[BackendSelection],
    results: Sequence[NormalizedBackendResult],
    policy: str = AGGREGATION_FAIL_DOMINANT_V1,
    acceptable_guarantees: Sequence[str] | None = None,
    fallback_accepted: bool = False,
) -> AggregationOutcome:
    """Dispatch to a versioned aggregation policy."""
    if policy != AGGREGATION_FAIL_DOMINANT_V1:
        raise ValueError(f"unsupported aggregation policy: {policy}")
    return aggregate_fail_dominant_v1(
        obligation_id=obligation_id,
        selected=selected,
        results=results,
        acceptable_guarantees=acceptable_guarantees,
        fallback_accepted=fallback_accepted,
    )
