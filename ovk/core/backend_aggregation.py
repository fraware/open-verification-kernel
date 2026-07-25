"""Backend result aggregation policies.

Versioned policy: ``ovk.aggregate.fail_dominant.v1``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from ovk.core.decision import (
    ClaimFinding,
    DecisionOutcome,
    aggregate_decision,
    decision_state_to_merge_recommendation,
)
from ovk.core.execution_models import (
    BackendSelection,
    ExecutionAttempt,
    FallbackPolicy,
    NormalizedBackendResult,
    TerminationKind,
)
from ovk.core.models import DecisionState, MergeRecommendation, VerificationStatus

AGGREGATION_FAIL_DOMINANT_V1 = "ovk.aggregate.fail_dominant.v1"

FALLBACK_BLOCKING_TERMINATIONS: frozenset[TerminationKind] = frozenset(
    {
        "timeout",
        "tool_error",
        "invalid_output",
        "resource_exhausted",
    }
)


@dataclass(frozen=True)
class AggregationOutcome:
    """Result of aggregating required and optional backend results."""

    status: VerificationStatus
    decision_state: DecisionState
    merge_recommendation: MergeRecommendation
    reason: str
    disagreement: dict[str, Any] | None = None
    warnings: tuple[str, ...] = ()
    quality_error: bool = False
    fallback_used: bool = False
    fallback_accepted: bool = False
    fallback_cause: str | None = None
    controlling_finding_ids: tuple[str, ...] = ()
    original_decision_state: DecisionState | None = None

    @staticmethod
    def from_lattice(
        *,
        status: VerificationStatus,
        outcome: DecisionOutcome,
        disagreement: dict[str, Any] | None = None,
        quality_error: bool = False,
        fallback_used: bool = False,
        fallback_accepted: bool = False,
        fallback_cause: str | None = None,
        extra_warnings: tuple[str, ...] = (),
    ) -> AggregationOutcome:
        recommendation = outcome.legacy_merge_override or outcome.merge_recommendation
        return AggregationOutcome(
            status=status,
            decision_state=outcome.decision_state,
            original_decision_state=outcome.original_decision_state,
            merge_recommendation=recommendation,
            reason=outcome.reason,
            disagreement=disagreement,
            warnings=tuple(list(extra_warnings) + list(outcome.warnings)),
            quality_error=quality_error,
            fallback_used=fallback_used,
            fallback_accepted=fallback_accepted,
            fallback_cause=fallback_cause,
            controlling_finding_ids=outcome.controlling_finding_ids,
        )


def evaluate_fallback_acceptance(
    *,
    policy: FallbackPolicy,
    selected: Sequence[BackendSelection],
    attempts: Sequence[ExecutionAttempt],
    results: Sequence[NormalizedBackendResult],
    acceptable_guarantees: Sequence[str] | None = None,
) -> tuple[bool, bool, str | None]:
    """Decide whether weaker fallback evidence may satisfy guarantee requirements (INV-017)."""
    acceptable = set(acceptable_guarantees or [])
    if not acceptable:
        return False, False, None

    attempts_by_backend = {item.backend: item for item in attempts}
    fallback_used = False
    fallback_cause: str | None = None

    for selection in selected:
        if not selection.required:
            continue
        result = next((item for item in results if item.backend == selection.backend), None)
        attempt = attempts_by_backend.get(selection.backend)
        if result is None or attempt is None:
            continue
        if result.status != VerificationStatus.PASS:
            continue
        if result.guarantee_type in acceptable:
            continue

        fallback_used = True
        fallback_cause = attempt.termination

        if attempt.termination in FALLBACK_BLOCKING_TERMINATIONS:
            return True, False, attempt.termination
        if not policy.allow_fallback:
            return True, False, attempt.termination
        if policy.outcome_for_termination(attempt.termination) in {"fail", "error"}:
            return True, False, attempt.termination
        if policy.fallback_backends and selection.backend not in policy.fallback_backends:
            return True, False, attempt.termination
        if policy.acceptable_fallback_guarantees and result.guarantee_type not in policy.acceptable_fallback_guarantees:
            return True, False, attempt.termination

    if fallback_used:
        return True, True, fallback_cause
    return False, False, None


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
    fallback_accepted: bool | None = None,
    fallback_policy: FallbackPolicy | None = None,
    attempts: Sequence[ExecutionAttempt] | None = None,
) -> AggregationOutcome:
    """Apply the fail-dominant aggregation decision table via the DecisionState lattice.

    Decision table (required backends):
    * any fail -> block
    * no fail, any error -> error (never allow)
    * no fail/error, any unknown/skipped -> unknown/skipped (strict: never allow)
    * every required pass with acceptable guarantees -> allow
    * no required result -> needs_review
    * selected vs executed mismatch -> needs_review + quality error
    * unaccepted weaker fallback -> needs_review (legacy alias require_stronger_check)

    Optional corroborators:
    * optional fail upgrades to block
    * optional unknown/error warns without invalidating required pass
    * optional pass cannot upgrade required unknown
    """
    policy = fallback_policy or FallbackPolicy()
    if attempts is not None:
        fallback_used, resolved_fallback_accepted, fallback_cause = evaluate_fallback_acceptance(
            policy=policy,
            selected=selected,
            attempts=attempts,
            results=results,
            acceptable_guarantees=acceptable_guarantees,
        )
    else:
        fallback_used = False
        fallback_cause = None
        resolved_fallback_accepted = bool(fallback_accepted)

    selected_required = [item for item in selected if item.required]
    selected_optional = [item for item in selected if not item.required]
    by_backend = _statuses_by_backend(results)
    executed = set(by_backend)
    selected_ids = {item.backend for item in selected}
    required_ids = {item.backend for item in selected_required}

    if selected_ids != executed:
        missing = sorted(selected_ids - executed)
        unexpected = sorted(executed - selected_ids)
        state = DecisionState.NEEDS_REVIEW
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            decision_state=state,
            original_decision_state=state,
            merge_recommendation=decision_state_to_merge_recommendation(state),
            reason=(f"selected and executed backend sets differ; missing={missing}; unexpected={unexpected}"),
            quality_error=True,
        )

    required_results = [item for item in results if item.backend in required_ids]
    optional_results = [item for item in results if item.backend in {s.backend for s in selected_optional}]

    if selected_required and not required_results:
        state = DecisionState.NEEDS_REVIEW
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            decision_state=state,
            original_decision_state=state,
            merge_recommendation=decision_state_to_merge_recommendation(state),
            reason="no required result exists",
            quality_error=True,
        )

    findings = [
        ClaimFinding(
            finding_id=f"{obligation_id}:{item.backend}",
            status=item.status,
            required=item.backend in required_ids,
        )
        for item in results
    ]

    disagreement = None
    if any(item.status == VerificationStatus.FAIL for item in optional_results):
        if required_results and any(item.status == VerificationStatus.PASS for item in required_results):
            disagreement = build_disagreement_artifact(
                obligation_id=obligation_id,
                results=list(results),
                resolution="block",
            )
    elif any(item.status == VerificationStatus.FAIL for item in required_results):
        if len({item.status for item in required_results}) > 1 or optional_results:
            disagreement = build_disagreement_artifact(
                obligation_id=obligation_id,
                results=list(results),
                resolution="block",
            )

    # Guarantee / fallback gate before allow.
    acceptable = set(acceptable_guarantees or [])
    stronger_check = False
    stronger_reason = ""
    if findings and all(
        (not item.required) or item.status == VerificationStatus.PASS for item in findings
    ):
        for item in required_results:
            if acceptable and item.guarantee_type not in acceptable and not resolved_fallback_accepted:
                stronger_check = True
                stronger_reason = (
                    f"required result from {item.backend} uses guarantee "
                    f"{item.guarantee_type!r} outside acceptable set"
                )
                break

    if stronger_check:
        state = DecisionState.NEEDS_REVIEW
        controlling = tuple(
            sorted(f"{obligation_id}:{item.backend}" for item in required_results)
        )
        return AggregationOutcome(
            status=VerificationStatus.UNKNOWN,
            decision_state=state,
            original_decision_state=state,
            merge_recommendation=MergeRecommendation.REQUIRE_STRONGER_CHECK,
            reason=stronger_reason,
            controlling_finding_ids=controlling,
            fallback_used=fallback_used,
            fallback_accepted=resolved_fallback_accepted,
            fallback_cause=fallback_cause,
        )

    lattice = aggregate_decision(findings, mode="strict")
    # Preserve historical wording for common paths when lattice reason is generic.
    reason = lattice.reason
    if lattice.decision_state == DecisionState.BLOCK and any(
        item.status == VerificationStatus.FAIL for item in optional_results
    ):
        reason = "optional corroborator reported fail"
    elif lattice.decision_state == DecisionState.BLOCK:
        reason = "required backend reported fail"
    elif lattice.original_decision_state in {
        DecisionState.ERROR,
        DecisionState.UNKNOWN,
        DecisionState.SKIPPED,
    }:
        reason = "required backend reported unknown, error, or skipped"
    elif lattice.decision_state == DecisionState.ALLOW:
        reason = "every required backend passed with acceptable guarantees"
    elif not required_results and not selected_required:
        reason = "no required backends were selected"

    # Map aggregate claim status for execution records.
    if lattice.decision_state == DecisionState.BLOCK:
        status = VerificationStatus.FAIL
    elif lattice.decision_state == DecisionState.ALLOW:
        status = VerificationStatus.PASS
    elif lattice.decision_state == DecisionState.ERROR:
        status = VerificationStatus.ERROR
    elif lattice.decision_state == DecisionState.SKIPPED:
        status = VerificationStatus.SKIPPED
    else:
        # needs_review / unknown — preserve historical UNKNOWN collapse
        status = VerificationStatus.UNKNOWN

    return AggregationOutcome.from_lattice(
        status=status,
        outcome=DecisionOutcome(
            decision_state=lattice.decision_state,
            original_decision_state=lattice.original_decision_state,
            merge_recommendation=lattice.merge_recommendation,
            reason=reason,
            controlling_finding_ids=lattice.controlling_finding_ids,
            finding_contributions=lattice.finding_contributions,
            mode=lattice.mode,
            warnings=lattice.warnings,
        ),
        disagreement=disagreement,
        fallback_used=fallback_used,
        fallback_accepted=resolved_fallback_accepted,
        fallback_cause=fallback_cause,
    )


def aggregate_results(
    *,
    obligation_id: str,
    selected: Sequence[BackendSelection],
    results: Sequence[NormalizedBackendResult],
    policy: str = AGGREGATION_FAIL_DOMINANT_V1,
    acceptable_guarantees: Sequence[str] | None = None,
    fallback_accepted: bool | None = None,
    fallback_policy: FallbackPolicy | None = None,
    attempts: Sequence[ExecutionAttempt] | None = None,
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
        fallback_policy=fallback_policy,
        attempts=attempts,
    )
