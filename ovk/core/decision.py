"""Merge decision lattice and aggregation for OVK evidence bundles.

Normative lattice (``DecisionState``):
    allow | block | needs_review | unknown | error | skipped

Hard rules:
- ``error`` never promotes to ``allow`` (strict and advisory)
- ``unknown`` never becomes ``allow`` in strict mode; advisory preserves ``unknown``
- Required ``skipped`` never silently allows in strict mode (``skipped`` or ``block``)
- Advisory preserves the honest lattice state via ``original_decision_state``
- Decisions list ``controlling_finding_ids`` and per-finding contributions

``merge_recommendation`` remains a deprecated alias of ``decision_state``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal, Sequence

from ovk.core.models import (
    DecisionState,
    EvidenceBundle,
    FindingContribution,
    MergeRecommendation,
    VerificationStatus,
)

Mode = Literal["strict", "advisory"]

# Claim severity for aggregation (higher = more severe / more controlling).
_CLAIM_SEVERITY: dict[VerificationStatus, int] = {
    VerificationStatus.PASS: 0,
    VerificationStatus.SKIPPED: 1,
    VerificationStatus.UNKNOWN: 2,
    VerificationStatus.ERROR: 3,
    VerificationStatus.FAIL: 4,
}

_DECISION_SEVERITY: dict[DecisionState, int] = {
    DecisionState.ALLOW: 0,
    DecisionState.NEEDS_REVIEW: 1,
    DecisionState.SKIPPED: 2,
    DecisionState.UNKNOWN: 3,
    DecisionState.ERROR: 4,
    DecisionState.BLOCK: 5,
}

# Legacy merge_recommendation ↔ DecisionState
_STATE_TO_LEGACY: dict[DecisionState, MergeRecommendation] = {
    DecisionState.ALLOW: MergeRecommendation.ALLOW,
    DecisionState.BLOCK: MergeRecommendation.BLOCK,
    DecisionState.NEEDS_REVIEW: MergeRecommendation.REQUIRE_HUMAN_REVIEW,
    DecisionState.UNKNOWN: MergeRecommendation.REQUIRE_HUMAN_REVIEW,
    DecisionState.ERROR: MergeRecommendation.REQUIRE_HUMAN_REVIEW,
    DecisionState.SKIPPED: MergeRecommendation.REQUIRE_HUMAN_REVIEW,
}

_LEGACY_TO_STATE: dict[str, DecisionState] = {
    "allow": DecisionState.ALLOW,
    "block": DecisionState.BLOCK,
    "needs_review": DecisionState.NEEDS_REVIEW,
    "require_human_review": DecisionState.NEEDS_REVIEW,
    "unknown": DecisionState.UNKNOWN,
    "error": DecisionState.ERROR,
    "skipped": DecisionState.SKIPPED,
    # Legacy aliases — not lattice members; map carefully (never to allow).
    "allow_with_warning": DecisionState.NEEDS_REVIEW,
    "require_stronger_check": DecisionState.NEEDS_REVIEW,
}

_UNKNOWN_POLICY_ALIASES = {
    "require_human_review": "needs_review",
    "needs_review": "needs_review",
    "block": "block",
    # Legacy: must not promote unknown → allow under the lattice.
    "allow_with_warning": "needs_review",
}


@dataclass(frozen=True)
class ClaimFinding:
    """One checker claim participating in lattice aggregation."""

    finding_id: str
    status: VerificationStatus
    required: bool = True


@dataclass(frozen=True)
class DecisionOutcome:
    """Full aggregated decision with attribution and legacy alias."""

    decision_state: DecisionState
    original_decision_state: DecisionState
    merge_recommendation: MergeRecommendation
    reason: str
    controlling_finding_ids: tuple[str, ...] = ()
    finding_contributions: tuple[FindingContribution, ...] = ()
    mode: Mode = "strict"
    warnings: tuple[str, ...] = ()
    # When stronger-check semantics apply, keep the specialized legacy alias.
    legacy_merge_override: MergeRecommendation | None = None

    def to_decision_dict(self) -> dict[str, Any]:
        """Serialize for evidence / bundle ``decision`` objects."""
        recommendation = self.legacy_merge_override or self.merge_recommendation
        return {
            "decision_state": self.decision_state.value,
            "original_decision_state": self.original_decision_state.value,
            "merge_recommendation": recommendation.value,
            "reason": self.reason,
            "controlling_finding_ids": list(self.controlling_finding_ids),
            "finding_contributions": [
                item.model_dump(mode="json") for item in self.finding_contributions
            ],
            "human_review_required": self.decision_state != DecisionState.ALLOW,
        }


def decision_state_to_merge_recommendation(state: DecisionState) -> MergeRecommendation:
    """Map a lattice state to the deprecated merge_recommendation alias."""
    return _STATE_TO_LEGACY[state]


def merge_recommendation_to_decision_state(value: str | MergeRecommendation | DecisionState) -> DecisionState:
    """Map a legacy or lattice string onto ``DecisionState``."""
    if isinstance(value, DecisionState):
        return value
    if isinstance(value, MergeRecommendation):
        raw = value.value
    else:
        raw = str(value).strip()
    if raw in _LEGACY_TO_STATE:
        return _LEGACY_TO_STATE[raw]
    return DecisionState.NEEDS_REVIEW


def normalize_unknown_policy(default_on_unknown: str) -> Literal["needs_review", "block"]:
    """Normalize unknown policy; never yields allow."""
    normalized = _UNKNOWN_POLICY_ALIASES.get(str(default_on_unknown).strip(), "needs_review")
    if normalized == "block":
        return "block"
    return "needs_review"


def normalize_required_skip_policy(
    default_on_required_skip: str,
) -> Literal["skipped", "block"]:
    """Normalize required-skip policy; never yields allow."""
    value = str(default_on_required_skip).strip().lower()
    if value == "block":
        return "block"
    return "skipped"


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


def findings_from_bundle(bundle: EvidenceBundle) -> list[ClaimFinding]:
    """Derive claim findings from an evidence bundle (all claims required by default)."""
    findings: list[ClaimFinding] = []
    for evidence in bundle.evidence:
        for claim in evidence.backend_claims:
            findings.append(
                ClaimFinding(
                    finding_id=f"{evidence.evidence_id}:{claim.backend}",
                    status=claim.status,
                    required=bool(getattr(claim, "required", True)),
                )
            )
    return findings


def _worst_status(statuses: Iterable[VerificationStatus]) -> VerificationStatus | None:
    worst: VerificationStatus | None = None
    worst_rank = -1
    for status in statuses:
        rank = _CLAIM_SEVERITY[status]
        if rank > worst_rank:
            worst = status
            worst_rank = rank
    return worst


def _base_state_from_status(status: VerificationStatus) -> DecisionState:
    if status == VerificationStatus.FAIL:
        return DecisionState.BLOCK
    if status == VerificationStatus.ERROR:
        return DecisionState.ERROR
    if status == VerificationStatus.UNKNOWN:
        return DecisionState.UNKNOWN
    if status == VerificationStatus.SKIPPED:
        return DecisionState.SKIPPED
    return DecisionState.ALLOW


def _apply_strict_policy(
    original: DecisionState,
    *,
    default_on_unknown: str,
    default_on_required_skip: str,
) -> DecisionState:
    """Apply strict-mode policy overlays without ever promoting to allow."""
    if original == DecisionState.ALLOW:
        return DecisionState.ALLOW
    if original == DecisionState.BLOCK:
        return DecisionState.BLOCK
    if original == DecisionState.ERROR:
        return DecisionState.ERROR
    if original == DecisionState.UNKNOWN:
        policy = normalize_unknown_policy(default_on_unknown)
        if policy == "block":
            return DecisionState.BLOCK
        return DecisionState.NEEDS_REVIEW
    if original == DecisionState.SKIPPED:
        skip_policy = normalize_required_skip_policy(default_on_required_skip)
        if skip_policy == "block":
            return DecisionState.BLOCK
        return DecisionState.SKIPPED
    return original


def _contributions_for(
    findings: Sequence[ClaimFinding],
    *,
    controlling_ids: set[str],
    warning_ids: set[str],
) -> tuple[FindingContribution, ...]:
    rows: list[FindingContribution] = []
    for finding in findings:
        if finding.finding_id in controlling_ids:
            contribution: Literal["controlling", "supporting", "non_controlling", "warning"] = "controlling"
        elif finding.finding_id in warning_ids:
            contribution = "warning"
        elif finding.status == VerificationStatus.PASS:
            contribution = "supporting"
        else:
            contribution = "non_controlling"
        rows.append(
            FindingContribution(
                finding_id=finding.finding_id,
                claim_status=finding.status,
                required=finding.required,
                contribution=contribution,
            )
        )
    return tuple(rows)


def aggregate_decision(
    findings: Sequence[ClaimFinding],
    *,
    mode: Mode = "strict",
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
    legacy_merge_override: MergeRecommendation | None = None,
) -> DecisionOutcome:
    """Aggregate claim findings into a ``DecisionState`` with attribution.

    Exhaustive fail-closed rules for required claims; optional claims may warn
    or upgrade fail→block but cannot upgrade a required non-pass to allow.
    """
    enforce = mode == "strict"
    required = [item for item in findings if item.required]
    optional = [item for item in findings if not item.required]
    warnings: list[str] = []

    if not findings:
        state = DecisionState.NEEDS_REVIEW
        return DecisionOutcome(
            decision_state=state,
            original_decision_state=state,
            merge_recommendation=decision_state_to_merge_recommendation(state),
            reason="no findings were provided for aggregation",
            mode=mode,
            legacy_merge_override=legacy_merge_override,
        )

    # Optional fail upgrades aggregate to block (fail-dominant).
    optional_fails = [item for item in optional if item.status == VerificationStatus.FAIL]
    required_fails = [item for item in required if item.status == VerificationStatus.FAIL]
    if optional_fails or required_fails:
        controllers = optional_fails + required_fails
        controlling_ids = {item.finding_id for item in controllers}
        original = DecisionState.BLOCK
        # Advisory preserves original (block); never rewrite to allow.
        decision_state = original
        return DecisionOutcome(
            decision_state=decision_state,
            original_decision_state=original,
            merge_recommendation=decision_state_to_merge_recommendation(decision_state),
            reason="one or more verification claims failed",
            controlling_finding_ids=tuple(sorted(controlling_ids)),
            finding_contributions=_contributions_for(
                findings, controlling_ids=controlling_ids, warning_ids=set()
            ),
            mode=mode,
            legacy_merge_override=legacy_merge_override,
        )

    required_non_pass = [item for item in required if item.status != VerificationStatus.PASS]
    if required_non_pass:
        worst = _worst_status(item.status for item in required_non_pass)
        assert worst is not None
        controllers = [item for item in required_non_pass if item.status == worst]
        # Include all findings at the controlling severity tier.
        controlling_ids = {item.finding_id for item in controllers}
        original = _base_state_from_status(worst)

        for item in optional:
            if item.status == VerificationStatus.PASS:
                warnings.append(
                    f"optional finding {item.finding_id} passed but cannot upgrade required {worst.value}"
                )

        if enforce:
            decision_state = _apply_strict_policy(
                original,
                default_on_unknown=default_on_unknown,
                default_on_required_skip=default_on_required_skip,
            )
        else:
            # Advisory: preserve original lattice state (never invent allow).
            decision_state = original

        if decision_state == DecisionState.ALLOW:
            # Hard invariant — unreachable by construction; keep fail-closed.
            decision_state = DecisionState.NEEDS_REVIEW

        reason = {
            DecisionState.ERROR: "one or more required verification claims returned error",
            DecisionState.UNKNOWN: "one or more required verification claims returned unknown",
            DecisionState.SKIPPED: "one or more required verification claims were skipped",
            DecisionState.BLOCK: "required verification outcome blocks merge under policy",
            DecisionState.NEEDS_REVIEW: "one or more required verification claims need human review",
        }.get(decision_state, "required verification claims did not all pass")

        return DecisionOutcome(
            decision_state=decision_state,
            original_decision_state=original,
            merge_recommendation=decision_state_to_merge_recommendation(decision_state),
            reason=reason,
            controlling_finding_ids=tuple(sorted(controlling_ids)),
            finding_contributions=_contributions_for(
                findings, controlling_ids=controlling_ids, warning_ids=set()
            ),
            mode=mode,
            warnings=tuple(warnings),
            legacy_merge_override=legacy_merge_override,
        )

    # All required pass (or no required findings).
    if not required:
        # No required selection — conservative review (never silent allow).
        state = DecisionState.NEEDS_REVIEW
        return DecisionOutcome(
            decision_state=state,
            original_decision_state=state,
            merge_recommendation=decision_state_to_merge_recommendation(state),
            reason="no required findings were selected",
            mode=mode,
            legacy_merge_override=legacy_merge_override,
        )

    warning_ids: set[str] = set()
    for item in optional:
        if item.status != VerificationStatus.PASS:
            warning_ids.add(item.finding_id)
            warnings.append(f"optional finding {item.finding_id} returned {item.status.value}")

    state = DecisionState.ALLOW
    controlling_ids = {item.finding_id for item in required}
    return DecisionOutcome(
        decision_state=state,
        original_decision_state=state,
        merge_recommendation=decision_state_to_merge_recommendation(state),
        reason="all required verification claims passed",
        controlling_finding_ids=tuple(sorted(controlling_ids)),
        finding_contributions=_contributions_for(
            findings, controlling_ids=controlling_ids, warning_ids=warning_ids
        ),
        mode=mode,
        warnings=tuple(warnings),
        legacy_merge_override=legacy_merge_override,
    )


def decide(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> DecisionState:
    """Compute the normative ``DecisionState`` for an evidence bundle."""
    outcome = aggregate_decision(
        findings_from_bundle(bundle),
        mode="strict" if enforce else "advisory",
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    )
    return outcome.decision_state


def decide_with_reason(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> dict[str, Any]:
    """Return decision lattice fields and deprecated merge_recommendation alias."""
    outcome = aggregate_decision(
        findings_from_bundle(bundle),
        mode="strict" if enforce else "advisory",
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    )
    return outcome.to_decision_dict()


# Back-compat helpers used by older tests / call sites.
def decide_merge_recommendation(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> MergeRecommendation:
    """Deprecated: return the legacy merge_recommendation alias for a bundle."""
    outcome = aggregate_decision(
        findings_from_bundle(bundle),
        mode="strict" if enforce else "advisory",
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    )
    return outcome.legacy_merge_override or outcome.merge_recommendation
