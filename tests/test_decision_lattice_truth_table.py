"""Exhaustive DecisionState lattice truth table (OVK-PR2 / OVK-03).

Covers claim statuses × {strict, advisory} × required/optional skip, plus
adversarial promotions that must never reach ALLOW in strict mode.
"""

from __future__ import annotations

import itertools

import pytest

from ovk.core.decision import (
    ClaimFinding,
    aggregate_decision,
    decide,
    decide_with_reason,
    merge_recommendation_to_decision_state,
)
from ovk.core.models import DecisionState, EvidenceBundle, MergeRecommendation, VerificationStatus

CLAIM_STATUSES = (
    VerificationStatus.PASS,
    VerificationStatus.FAIL,
    VerificationStatus.UNKNOWN,
    VerificationStatus.ERROR,
    VerificationStatus.SKIPPED,
)

MODES = ("strict", "advisory")


def _finding(
    status: VerificationStatus,
    *,
    finding_id: str = "f1",
    required: bool = True,
) -> ClaimFinding:
    return ClaimFinding(finding_id=finding_id, status=status, required=required)


def _bundle_with_claims(*statuses: VerificationStatus, required: bool = True) -> EvidenceBundle:
    claims = [
        {
            "backend": f"backend-{index}",
            "guarantee_type": "test",
            "status": status.value,
            "required": required,
        }
        for index, status in enumerate(statuses)
    ]
    return EvidenceBundle.model_validate(
        {
            "bundle_id": "bundle-lattice",
            "schema_version": "ovk.bundle.v1",
            "subject": {"repo": "example/repo", "head_sha": "abc"},
            "evidence": [
                {
                    "evidence_id": "ev-lattice",
                    "schema_version": "ovk.evidence.v1",
                    "subject": {"repo": "example/repo", "head_sha": "abc"},
                    "intent": {"intent_id": "test", "title": "test"},
                    "backend_claims": claims,
                    "decision": {"merge_recommendation": "require_human_review"},
                }
            ],
            "decision": {"merge_recommendation": "require_human_review"},
        }
    )


@pytest.mark.parametrize("status,mode", list(itertools.product(CLAIM_STATUSES, MODES)))
def test_single_required_claim_truth_table(status: VerificationStatus, mode: str) -> None:
    outcome = aggregate_decision([_finding(status)], mode=mode)  # type: ignore[arg-type]
    if status == VerificationStatus.PASS:
        assert outcome.decision_state == DecisionState.ALLOW
        assert outcome.original_decision_state == DecisionState.ALLOW
    elif status == VerificationStatus.FAIL:
        assert outcome.decision_state == DecisionState.BLOCK
        assert outcome.original_decision_state == DecisionState.BLOCK
    elif status == VerificationStatus.ERROR:
        assert outcome.decision_state == DecisionState.ERROR
        assert outcome.original_decision_state == DecisionState.ERROR
        assert outcome.decision_state != DecisionState.ALLOW
    elif status == VerificationStatus.UNKNOWN:
        assert outcome.original_decision_state == DecisionState.UNKNOWN
        if mode == "strict":
            assert outcome.decision_state == DecisionState.NEEDS_REVIEW
            assert outcome.decision_state != DecisionState.ALLOW
        else:
            assert outcome.decision_state == DecisionState.UNKNOWN
            assert outcome.decision_state != DecisionState.ALLOW
    elif status == VerificationStatus.SKIPPED:
        assert outcome.original_decision_state == DecisionState.SKIPPED
        assert outcome.decision_state == DecisionState.SKIPPED
        assert outcome.decision_state != DecisionState.ALLOW


@pytest.mark.parametrize("status", CLAIM_STATUSES)
def test_optional_non_fail_does_not_block_required_pass(status: VerificationStatus) -> None:
    findings = [
        _finding(VerificationStatus.PASS, finding_id="req", required=True),
        _finding(status, finding_id="opt", required=False),
    ]
    for mode in MODES:
        outcome = aggregate_decision(findings, mode=mode)  # type: ignore[arg-type]
        if status == VerificationStatus.FAIL:
            assert outcome.decision_state == DecisionState.BLOCK
        else:
            assert outcome.decision_state == DecisionState.ALLOW
            if status != VerificationStatus.PASS:
                assert "opt" in {
                    row.finding_id for row in outcome.finding_contributions if row.contribution == "warning"
                }


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("skip_policy", ("skipped", "block"))
def test_required_skipped_never_allows(mode: str, skip_policy: str) -> None:
    outcome = aggregate_decision(
        [_finding(VerificationStatus.SKIPPED)],
        mode=mode,  # type: ignore[arg-type]
        default_on_required_skip=skip_policy,
    )
    assert outcome.decision_state != DecisionState.ALLOW
    if mode == "strict" and skip_policy == "block":
        assert outcome.decision_state == DecisionState.BLOCK
    else:
        assert outcome.decision_state == DecisionState.SKIPPED
    assert outcome.original_decision_state == DecisionState.SKIPPED


@pytest.mark.parametrize("mode", MODES)
def test_adversarial_error_never_allows(mode: str) -> None:
    """ERROR→ALLOW must be impossible in both modes."""
    outcome = aggregate_decision(
        [
            _finding(VerificationStatus.ERROR, finding_id="err"),
            _finding(VerificationStatus.PASS, finding_id="pass-optional", required=False),
        ],
        mode=mode,  # type: ignore[arg-type]
        default_on_unknown="allow_with_warning",
    )
    assert outcome.decision_state == DecisionState.ERROR
    assert outcome.decision_state != DecisionState.ALLOW
    assert "err" in outcome.controlling_finding_ids


@pytest.mark.parametrize("unknown_policy", ("require_human_review", "block", "allow_with_warning", "needs_review"))
def test_adversarial_unknown_never_allows_in_strict(unknown_policy: str) -> None:
    """UNKNOWN→ALLOW must be impossible in strict mode, including legacy allow_with_warning."""
    outcome = aggregate_decision(
        [_finding(VerificationStatus.UNKNOWN, finding_id="unk")],
        mode="strict",
        default_on_unknown=unknown_policy,
    )
    assert outcome.decision_state != DecisionState.ALLOW
    assert outcome.original_decision_state == DecisionState.UNKNOWN
    if unknown_policy == "block":
        assert outcome.decision_state == DecisionState.BLOCK
    else:
        assert outcome.decision_state == DecisionState.NEEDS_REVIEW


def test_advisory_unknown_preserves_original_state() -> None:
    outcome = aggregate_decision([_finding(VerificationStatus.UNKNOWN)], mode="advisory")
    assert outcome.decision_state == DecisionState.UNKNOWN
    assert outcome.original_decision_state == DecisionState.UNKNOWN
    payload = outcome.to_decision_dict()
    assert payload["decision_state"] == "unknown"
    assert payload["original_decision_state"] == "unknown"
    # Deprecated alias maps onto require_human_review, not invent allow_with_warning.
    assert payload["merge_recommendation"] == MergeRecommendation.REQUIRE_HUMAN_REVIEW.value


def test_multi_finding_control_attribution() -> None:
    outcome = aggregate_decision(
        [
            _finding(VerificationStatus.PASS, finding_id="a"),
            _finding(VerificationStatus.FAIL, finding_id="b"),
            _finding(VerificationStatus.ERROR, finding_id="c"),
        ],
        mode="strict",
    )
    assert outcome.decision_state == DecisionState.BLOCK
    assert outcome.controlling_finding_ids == ("b",)
    by_id = {row.finding_id: row.contribution for row in outcome.finding_contributions}
    assert by_id["b"] == "controlling"
    assert by_id["a"] == "supporting"
    assert by_id["c"] == "non_controlling"


def test_error_dominates_unknown_for_control() -> None:
    outcome = aggregate_decision(
        [
            _finding(VerificationStatus.UNKNOWN, finding_id="u"),
            _finding(VerificationStatus.ERROR, finding_id="e"),
        ],
        mode="strict",
    )
    assert outcome.decision_state == DecisionState.ERROR
    assert outcome.controlling_finding_ids == ("e",)


def test_optional_pass_cannot_upgrade_required_unknown() -> None:
    outcome = aggregate_decision(
        [
            _finding(VerificationStatus.UNKNOWN, finding_id="req"),
            _finding(VerificationStatus.PASS, finding_id="opt", required=False),
        ],
        mode="strict",
    )
    assert outcome.decision_state != DecisionState.ALLOW
    assert "req" in outcome.controlling_finding_ids
    assert any("cannot upgrade" in warning for warning in outcome.warnings)


def test_decide_bundle_emits_lattice_fields() -> None:
    bundle = _bundle_with_claims(VerificationStatus.ERROR)
    payload = decide_with_reason(bundle, enforce=True)
    assert payload["decision_state"] == DecisionState.ERROR.value
    assert payload["original_decision_state"] == DecisionState.ERROR.value
    assert payload["merge_recommendation"] == MergeRecommendation.REQUIRE_HUMAN_REVIEW.value
    assert payload["controlling_finding_ids"]
    assert decide(bundle, enforce=True) == DecisionState.ERROR


def test_legacy_alias_round_trip() -> None:
    assert merge_recommendation_to_decision_state("require_human_review") == DecisionState.NEEDS_REVIEW
    assert merge_recommendation_to_decision_state("allow_with_warning") == DecisionState.NEEDS_REVIEW
    assert merge_recommendation_to_decision_state("require_stronger_check") == DecisionState.NEEDS_REVIEW
    assert merge_recommendation_to_decision_state(DecisionState.ERROR) == DecisionState.ERROR


@pytest.mark.parametrize(
    "left,right",
    list(itertools.product(CLAIM_STATUSES, CLAIM_STATUSES)),
)
def test_pairwise_required_claims_never_allow_on_bad(
    left: VerificationStatus, right: VerificationStatus
) -> None:
    """Every pair of required claims: any non-pass forbids ALLOW in strict mode."""
    outcome = aggregate_decision(
        [
            _finding(left, finding_id="left"),
            _finding(right, finding_id="right"),
        ],
        mode="strict",
    )
    if left == VerificationStatus.PASS and right == VerificationStatus.PASS:
        assert outcome.decision_state == DecisionState.ALLOW
    else:
        assert outcome.decision_state != DecisionState.ALLOW


@pytest.mark.parametrize("status", CLAIM_STATUSES)
@pytest.mark.parametrize("required_skip", (True, False))
def test_skip_required_vs_optional_matrix(status: VerificationStatus, required_skip: bool) -> None:
    """Required/optional skip combinations against each claim status under both modes."""
    if status != VerificationStatus.SKIPPED and not required_skip:
        # Focus skip matrix on skip claims; other statuses covered elsewhere.
        pytest.skip("non-skip optional covered by optional matrix")
    findings = [
        _finding(VerificationStatus.PASS, finding_id="req-pass", required=True),
        _finding(status, finding_id="focus", required=required_skip),
    ]
    for mode in MODES:
        outcome = aggregate_decision(findings, mode=mode)  # type: ignore[arg-type]
        if status == VerificationStatus.PASS:
            assert outcome.decision_state == DecisionState.ALLOW
        elif status == VerificationStatus.FAIL:
            assert outcome.decision_state == DecisionState.BLOCK
        elif required_skip:
            assert outcome.decision_state != DecisionState.ALLOW
        else:
            # Optional skip/unknown/error beside required pass → allow with warning.
            if status in {
                VerificationStatus.SKIPPED,
                VerificationStatus.UNKNOWN,
                VerificationStatus.ERROR,
            }:
                assert outcome.decision_state == DecisionState.ALLOW
