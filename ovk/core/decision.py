"""Merge decision lattice and conservative bundle aggregation.

The checker-status lattice and the authorization decision lattice are related but
not interchangeable. A backend can correctly return ``pass`` while an evidence
producer still requires review because coverage is incomplete, source material
is untrusted, a weaker guarantee was used, or another semantic precondition was
not discharged.

Consequently bundle aggregation obeys a monotonicity invariant:

    a bundle MUST NOT be more permissive than any authoritative evidence item.

``merge_recommendation`` is retained as a compatibility alias for
``DecisionState``. New code should reason about ``DecisionState`` directly.
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

# Claim severity for backend-result aggregation. Higher is more controlling.
_CLAIM_SEVERITY: dict[VerificationStatus, int] = {
    VerificationStatus.PASS: 0,
    VerificationStatus.SKIPPED: 1,
    VerificationStatus.UNKNOWN: 2,
    VerificationStatus.ERROR: 3,
    VerificationStatus.FAIL: 4,
}

# Authorization severity. Higher values are never less restrictive than lower
# values. NEEDS_REVIEW is deliberately distinct from UNKNOWN/ERROR/SKIPPED even
# though all prevent an allow decision.
_DECISION_SEVERITY: dict[DecisionState, int] = {
    DecisionState.ALLOW: 0,
    DecisionState.NEEDS_REVIEW: 1,
    DecisionState.SKIPPED: 2,
    DecisionState.UNKNOWN: 3,
    DecisionState.ERROR: 4,
    DecisionState.BLOCK: 5,
}

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
    # Compatibility aliases are intentionally never interpreted as allow.
    "allow_with_warning": DecisionState.NEEDS_REVIEW,
    "require_stronger_check": DecisionState.NEEDS_REVIEW,
}

_UNKNOWN_POLICY_ALIASES = {
    "require_human_review": "needs_review",
    "needs_review": "needs_review",
    "block": "block",
    # Historical policy value. Under the lattice an unknown may not become an
    # allow decision simply because an older config said allow_with_warning.
    "allow_with_warning": "needs_review",
}


@dataclass(frozen=True)
class ClaimFinding:
    """One checker claim participating in checker-level aggregation."""

    finding_id: str
    status: VerificationStatus
    required: bool = True


@dataclass(frozen=True)
class DecisionOutcome:
    """Aggregated authorization decision plus attribution."""

    decision_state: DecisionState
    original_decision_state: DecisionState
    merge_recommendation: MergeRecommendation
    reason: str
    controlling_finding_ids: tuple[str, ...] = ()
    finding_contributions: tuple[FindingContribution, ...] = ()
    mode: Mode = "strict"
    warnings: tuple[str, ...] = ()
    legacy_merge_override: MergeRecommendation | None = None

    def to_decision_dict(self) -> dict[str, Any]:
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
    """Map a lattice state to the legacy recommendation vocabulary."""
    return _STATE_TO_LEGACY[state]


def merge_recommendation_to_decision_state(
    value: str | MergeRecommendation | DecisionState,
) -> DecisionState:
    """Map a legacy or lattice value onto ``DecisionState`` fail-closed."""
    if isinstance(value, DecisionState):
        return value
    raw = value.value if isinstance(value, MergeRecommendation) else str(value).strip()
    return _LEGACY_TO_STATE.get(raw, DecisionState.NEEDS_REVIEW)


def normalize_unknown_policy(default_on_unknown: str) -> Literal["needs_review", "block"]:
    """Normalize unknown policy; the result can never authorize allow."""
    normalized = _UNKNOWN_POLICY_ALIASES.get(str(default_on_unknown).strip(), "needs_review")
    return "block" if normalized == "block" else "needs_review"


def normalize_required_skip_policy(
    default_on_required_skip: str,
) -> Literal["skipped", "block"]:
    """Normalize required-skip policy; the result can never authorize allow."""
    return "block" if str(default_on_required_skip).strip().lower() == "block" else "skipped"


def evidence_has_status(bundle: EvidenceBundle, status: VerificationStatus) -> bool:
    return any(
        claim.status == status
        for evidence in bundle.evidence
        for claim in evidence.backend_claims
    )


def evidence_has_unknown_like(bundle: EvidenceBundle) -> bool:
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


def findings_from_bundle(bundle: EvidenceBundle) -> list[ClaimFinding]:
    """Derive checker findings without conflating evidence-level decisions."""
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
    """Apply strict-mode policy overlays without ever promoting authority."""
    if original in {DecisionState.ALLOW, DecisionState.BLOCK, DecisionState.ERROR}:
        return original
    if original == DecisionState.UNKNOWN:
        return (
            DecisionState.BLOCK
            if normalize_unknown_policy(default_on_unknown) == "block"
            else DecisionState.NEEDS_REVIEW
        )
    if original == DecisionState.SKIPPED:
        return (
            DecisionState.BLOCK
            if normalize_required_skip_policy(default_on_required_skip) == "block"
            else DecisionState.SKIPPED
        )
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
            contribution: Literal[
                "controlling", "supporting", "non_controlling", "warning"
            ] = "controlling"
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
    """Aggregate checker findings using fail-dominant required semantics."""
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

    optional_fails = [item for item in optional if item.status == VerificationStatus.FAIL]
    required_fails = [item for item in required if item.status == VerificationStatus.FAIL]
    if optional_fails or required_fails:
        controllers = optional_fails + required_fails
        controlling_ids = {item.finding_id for item in controllers}
        state = DecisionState.BLOCK
        return DecisionOutcome(
            decision_state=state,
            original_decision_state=state,
            merge_recommendation=decision_state_to_merge_recommendation(state),
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
        controlling_ids = {item.finding_id for item in controllers}
        original = _base_state_from_status(worst)

        for item in optional:
            if item.status == VerificationStatus.PASS:
                warnings.append(
                    f"optional finding {item.finding_id} passed but cannot upgrade required {worst.value}"
                )

        state = (
            _apply_strict_policy(
                original,
                default_on_unknown=default_on_unknown,
                default_on_required_skip=default_on_required_skip,
            )
            if enforce
            else original
        )
        if state == DecisionState.ALLOW:  # defensive, unreachable by construction
            state = DecisionState.NEEDS_REVIEW

        reason = {
            DecisionState.ERROR: "one or more required verification claims returned error",
            DecisionState.UNKNOWN: "one or more required verification claims returned unknown",
            DecisionState.SKIPPED: "one or more required verification claims were skipped",
            DecisionState.BLOCK: "required verification outcome blocks merge under policy",
            DecisionState.NEEDS_REVIEW: "one or more required verification claims need review",
        }.get(state, "required verification claims did not all pass")

        return DecisionOutcome(
            decision_state=state,
            original_decision_state=original,
            merge_recommendation=decision_state_to_merge_recommendation(state),
            reason=reason,
            controlling_finding_ids=tuple(sorted(controlling_ids)),
            finding_contributions=_contributions_for(
                findings, controlling_ids=controlling_ids, warning_ids=set()
            ),
            mode=mode,
            warnings=tuple(warnings),
            legacy_merge_override=legacy_merge_override,
        )

    if not required:
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


def _raw_evidence_decision(evidence: Any) -> tuple[DecisionState, MergeRecommendation | None]:
    """Read one evidence-level authorization decision conservatively.

    ``decision_state`` is normative when present. Legacy evidence is mapped from
    ``merge_recommendation``. Missing or unrecognized authorization state is a
    review requirement, never an implicit allow.
    """
    decision = evidence.decision if isinstance(getattr(evidence, "decision", None), dict) else {}
    if decision.get("decision_state") is not None:
        state = merge_recommendation_to_decision_state(str(decision["decision_state"]))
    elif decision.get("merge_recommendation") is not None:
        state = merge_recommendation_to_decision_state(str(decision["merge_recommendation"]))
    else:
        state = DecisionState.NEEDS_REVIEW

    legacy: MergeRecommendation | None = None
    raw_legacy = str(decision.get("merge_recommendation", "")).strip()
    if raw_legacy == MergeRecommendation.REQUIRE_STRONGER_CHECK.value:
        legacy = MergeRecommendation.REQUIRE_STRONGER_CHECK
    return state, legacy


def _evidence_floor_state(
    raw: DecisionState,
    *,
    mode: Mode,
    default_on_unknown: str,
    default_on_required_skip: str,
) -> DecisionState:
    if mode == "advisory":
        return raw
    return _apply_strict_policy(
        raw,
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    )


def aggregate_bundle_decision(
    bundle: EvidenceBundle,
    *,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> DecisionOutcome:
    """Aggregate checker results and enforce evidence-decision monotonicity.

    Evidence-level decisions encode semantic qualifications that checker status
    alone cannot express (coverage, material trust, guarantee strength, fallback
    acceptance, etc.). They therefore form an authorization floor. A downstream
    bundle may become *more* restrictive, but never more permissive.
    """
    mode: Mode = "strict" if enforce else "advisory"
    claim_outcome = aggregate_decision(
        findings_from_bundle(bundle),
        mode=mode,
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    )

    restrictions: list[tuple[str, DecisionState, DecisionState, MergeRecommendation | None]] = []
    for evidence in bundle.evidence:
        raw, legacy = _raw_evidence_decision(evidence)
        effective = _evidence_floor_state(
            raw,
            mode=mode,
            default_on_unknown=default_on_unknown,
            default_on_required_skip=default_on_required_skip,
        )
        restrictions.append((evidence.evidence_id, raw, effective, legacy))

    if not restrictions:
        return claim_outcome

    worst_effective_rank = max(_DECISION_SEVERITY[item[2]] for item in restrictions)
    claim_rank = _DECISION_SEVERITY[claim_outcome.decision_state]
    if claim_rank >= worst_effective_rank:
        return claim_outcome

    controlling = [
        item for item in restrictions if _DECISION_SEVERITY[item[2]] == worst_effective_rank
    ]
    effective_state = controlling[0][2]
    worst_raw = max(
        [claim_outcome.original_decision_state, *[item[1] for item in controlling]],
        key=lambda state: _DECISION_SEVERITY[state],
    )
    evidence_ids = tuple(sorted(f"evidence:{item[0]}:decision" for item in controlling))
    controlling_ids = tuple(sorted(set(claim_outcome.controlling_finding_ids) | set(evidence_ids)))

    legacy_override = None
    if effective_state == DecisionState.NEEDS_REVIEW and any(
        item[3] == MergeRecommendation.REQUIRE_STRONGER_CHECK for item in controlling
    ):
        legacy_override = MergeRecommendation.REQUIRE_STRONGER_CHECK

    reason = (
        "evidence-level authorization restriction controls bundle decision; "
        "backend claim status cannot promote a stricter evidence decision"
    )
    warnings = tuple(claim_outcome.warnings) + tuple(
        f"{item[0]} requires {item[2].value}" for item in controlling
    )
    return DecisionOutcome(
        decision_state=effective_state,
        original_decision_state=worst_raw,
        merge_recommendation=decision_state_to_merge_recommendation(effective_state),
        reason=reason,
        controlling_finding_ids=controlling_ids,
        finding_contributions=claim_outcome.finding_contributions,
        mode=mode,
        warnings=warnings,
        legacy_merge_override=legacy_override,
    )


def decide(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> DecisionState:
    """Compute the normative bundle decision with monotonic evidence floors."""
    return aggregate_bundle_decision(
        bundle,
        enforce=enforce,
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    ).decision_state


def decide_with_reason(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> dict[str, Any]:
    """Return the normative decision plus compatibility aliases."""
    return aggregate_bundle_decision(
        bundle,
        enforce=enforce,
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    ).to_decision_dict()


def decide_merge_recommendation(
    bundle: EvidenceBundle,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
    default_on_required_skip: str = "skipped",
) -> MergeRecommendation:
    """Deprecated compatibility helper for legacy callers."""
    outcome = aggregate_bundle_decision(
        bundle,
        enforce=enforce,
        default_on_unknown=default_on_unknown,
        default_on_required_skip=default_on_required_skip,
    )
    return outcome.legacy_merge_override or outcome.merge_recommendation
