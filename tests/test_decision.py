from ovk.core.decision import decide
from ovk.core.models import EvidenceBundle, MergeRecommendation


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
    assert decide(make_bundle("fail"), enforce=True) == MergeRecommendation.BLOCK


def test_unknown_requires_human_review_in_enforce_mode() -> None:
    assert decide(make_bundle("unknown"), enforce=True) == MergeRecommendation.REQUIRE_HUMAN_REVIEW


def test_pass_allows() -> None:
    assert decide(make_bundle("pass"), enforce=True) == MergeRecommendation.ALLOW
