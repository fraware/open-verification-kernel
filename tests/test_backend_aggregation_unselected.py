from ovk.core.backend_aggregation import aggregate_fail_dominant_v1
from ovk.core.execution_models import BackendSelection, NormalizedBackendResult
from ovk.core.models import MergeRecommendation, VerificationStatus


def _result(backend: str, status: VerificationStatus = VerificationStatus.PASS) -> NormalizedBackendResult:
    return NormalizedBackendResult(
        attempt_id=f"attempt-{backend}",
        backend=backend,
        status=status,
        guarantee_type="deterministic_witness",
    )


def test_unselected_backend_result_is_a_quality_error() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obligation-1",
        selected=[
            BackendSelection(
                backend="required-backend",
                reason="selected primary",
                expected_guarantee="deterministic_witness",
                required=True,
            )
        ],
        results=[
            _result("required-backend"),
            _result("unselected-backend"),
        ],
        acceptable_guarantees=["deterministic_witness"],
    )

    assert outcome.status == VerificationStatus.UNKNOWN
    assert outcome.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW
    assert outcome.quality_error is True
    assert "unexpected=['unselected-backend']" in outcome.reason
