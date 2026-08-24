from ovk.core.decision import decide, decide_merge_recommendation, decide_with_reason
from ovk.core.models import DecisionState, EvidenceBundle, MergeRecommendation


def make_bundle(
    status: str,
    *,
    evidence_recommendation: str | None = None,
    evidence_decision_state: str | None = None,
) -> EvidenceBundle:
    if evidence_recommendation is None:
        evidence_recommendation = {
            "pass": "allow",
            "fail": "block",
            "unknown": "require_human_review",
            "error": "require_human_review",
            "skipped": "require_human_review",
        }.get(status, "require_human_review")
    decision = {"merge_recommendation": evidence_recommendation}
    if evidence_decision_state is not None:
        decision["decision_state"] = evidence_decision_state
    return EvidenceBundle.model_validate(
        {
            "bundle_id": "bundle-test",
            "schema_version": "ovk.bundle.v1",
            "subject": {"repo": "example/repo", "head_sha": "abc"},
            "evidence": [
                {
                    "evidence_id": "ev-test",
                    "schema_version": "ovk.evidence.v1",
                    "subject": {"repo": "example/repo", "head_sha": "abc"},
                    "intent": {"intent_id": "test", "title": "test"},
                    "backend_claims": [
                        {
                            "backend": "test-backend",
                            "guarantee_type": "test",
                            "status": status,
                        }
                    ],
                    "decision": decision,
                }
            ],
            "decision": {"merge_recommendation": "require_human_review"},
        }
    )


def test_fail_blocks_in_enforce_mode() -> None:
    assert decide(make_bundle("fail"), enforce=True) == DecisionState.BLOCK


def test_unknown_requires_human_review_in_enforce_mode() -> None:
    assert decide(make_bundle("unknown"), enforce=True) == DecisionState.NEEDS_REVIEW


def test_unknown_blocks_when_default_on_unknown_is_block() -> None:
    assert decide(make_bundle("unknown"), enforce=True, default_on_unknown="block") == DecisionState.BLOCK


def test_unknown_legacy_allow_with_warning_never_allows_in_strict() -> None:
    state = decide(make_bundle("unknown"), enforce=True, default_on_unknown="allow_with_warning")
    assert state == DecisionState.NEEDS_REVIEW
    assert state != DecisionState.ALLOW
    assert decide_merge_recommendation(
        make_bundle("unknown"), enforce=True, default_on_unknown="allow_with_warning"
    ) == MergeRecommendation.REQUIRE_HUMAN_REVIEW


def test_pass_allows_when_evidence_authorizes_allow() -> None:
    assert decide(make_bundle("pass", evidence_recommendation="allow"), enforce=True) == DecisionState.ALLOW


def test_pass_claim_cannot_promote_evidence_review() -> None:
    bundle = make_bundle("pass", evidence_recommendation="require_human_review")
    assert decide(bundle, enforce=True) == DecisionState.NEEDS_REVIEW
    payload = decide_with_reason(bundle, enforce=True)
    assert payload["merge_recommendation"] == "require_human_review"
    assert "evidence:ev-test:decision" in payload["controlling_finding_ids"]


def test_pass_claim_cannot_promote_require_stronger_check() -> None:
    bundle = make_bundle("pass", evidence_recommendation="require_stronger_check")
    assert decide(bundle, enforce=True) == DecisionState.NEEDS_REVIEW
    assert decide_merge_recommendation(bundle, enforce=True) == MergeRecommendation.REQUIRE_STRONGER_CHECK


def test_pass_claim_cannot_promote_evidence_block() -> None:
    bundle = make_bundle("pass", evidence_recommendation="block")
    assert decide(bundle, enforce=True) == DecisionState.BLOCK


def test_normative_decision_state_takes_precedence_over_legacy_alias() -> None:
    bundle = make_bundle(
        "pass",
        evidence_recommendation="allow",
        evidence_decision_state="needs_review",
    )
    assert decide(bundle, enforce=True) == DecisionState.NEEDS_REVIEW


def test_claim_failure_remains_more_restrictive_than_evidence_allow() -> None:
    bundle = make_bundle("fail", evidence_recommendation="allow")
    assert decide(bundle, enforce=True) == DecisionState.BLOCK


def test_decide_with_reason_emits_decision_state() -> None:
    payload = decide_with_reason(make_bundle("error"), enforce=True)
    assert payload["decision_state"] == "error"
    assert payload["original_decision_state"] == "error"
    assert payload["merge_recommendation"] == "require_human_review"
    assert payload["controlling_finding_ids"]
