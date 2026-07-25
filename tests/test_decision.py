from ovk.core.decision import decide, decide_merge_recommendation, decide_with_reason
from ovk.core.models import DecisionState, EvidenceBundle, MergeRecommendation


def make_bundle(status: str) -> EvidenceBundle:
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
                    "decision": {"merge_recommendation": "require_human_review"},
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


def test_pass_allows() -> None:
    assert decide(make_bundle("pass"), enforce=True) == DecisionState.ALLOW


def test_decide_with_reason_emits_decision_state() -> None:
    payload = decide_with_reason(make_bundle("error"), enforce=True)
    assert payload["decision_state"] == "error"
    assert payload["original_decision_state"] == "error"
    assert payload["merge_recommendation"] == "require_human_review"
    assert payload["controlling_finding_ids"]
