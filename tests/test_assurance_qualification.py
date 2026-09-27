from __future__ import annotations

from ovk.core.assurance_qualification import (
    AssuranceQualificationCaseResult,
    AssuranceQualificationSuite,
    _qualification_status,
    load_assurance_qualification_suite,
    run_assurance_qualification_suite,
    validate_assurance_qualification_report,
)
from pathlib import Path


SUITE_PATH = Path(
    "benchmarks/assurance_qualification/suite.v1.json"
)


def _external_result(
    *,
    repository: str,
    index: int,
    unsafe: bool,
    false_assurance: bool = False,
) -> AssuranceQualificationCaseResult:
    head_established = not unsafe or false_assurance
    return AssuranceQualificationCaseResult(
        case_id=f"{repository}-{index}",
        repository=repository,
        validation_class="independent_external",
        safety_label="unsafe" if unsafe else "safe",
        expected_head_assurance=(
            "not_established" if unsafe else "established"
        ),
        automatic_status="complete",
        assurance_available=True,
        head_established=head_established,
        semantic_coverage_complete=True,
        expectation_met=not false_assurance,
        unsafe_false_assurance=false_assurance,
        benign_open=False,
        fresh_effect_count=1,
        reused_effect_count=0,
        elapsed_ms=10.0,
        changed_files=["routes.py"],
        head_statuses={
            "G": "established" if head_established else "violated"
        },
        reason_codes=[],
        governance_review_required=False,
        human_adjudicated=True,
        human_review_minutes=1.0,
    )


def test_committed_qualification_suite_executes_expected_product_behavior() -> None:
    suite = load_assurance_qualification_suite(SUITE_PATH)
    report = run_assurance_qualification_suite(suite)

    validate_assurance_qualification_report(report)
    assert report.cases_total == 10
    assert all(item.expectation_met for item in report.results)
    assert report.metrics.unsafe_false_assurance_count == 0
    assert report.metrics.unsafe_detection_rate == 1.0

    # The unsupported control-flow case is intentionally a benign open and is
    # part of the economic burden rather than being hidden from the metrics.
    assert report.metrics.benign_open_count == 1
    assert report.metrics.semantic_coverage_rate < 1.0
    assert report.metrics.coverage_gap_case_count == 2
    assert report.metrics.coverage_gap_reason_counts == {
        "control_flow_outside_profile": 1,
        "required_scope_postcondition_missing": 1,
    }
    assert report.metrics.benign_open_reason_counts[
        "coverage:control_flow_outside_profile"
    ] == 1
    assert report.metrics.benign_open_reason_counts[
        "guarantee_status:unknown"
    ] == 1

    # Public-development and internal cases cannot satisfy the external gate.
    assert report.evidence_classes.independent_external_cases == 0
    assert report.qualification.status == "internal_signal_only"
    assert report.qualification.production_gate_met is False


def test_external_gate_requires_two_repositories_and_human_sample_depth() -> None:
    results: list[AssuranceQualificationCaseResult] = []
    for repository in ("external/a", "external/b"):
        for index in range(30):
            results.append(
                _external_result(
                    repository=repository,
                    index=index,
                    unsafe=(index % 2 == 0),
                )
            )

    status = _qualification_status(results)
    assert status.status == "production_gate_eligible"
    assert status.production_gate_met is True
    assert status.reason_codes == []


def test_external_unsafe_false_assurance_blocks_production_gate() -> None:
    results: list[AssuranceQualificationCaseResult] = []
    for repository in ("external/a", "external/b"):
        for index in range(30):
            results.append(
                _external_result(
                    repository=repository,
                    index=index,
                    unsafe=(index % 2 == 0),
                    false_assurance=(
                        repository == "external/b" and index == 0
                    ),
                )
            )

    status = _qualification_status(results)
    assert status.production_gate_met is False
    assert "unsafe_false_assurance_observed_external" in status.reason_codes
    assert (
        "external_unsafe_detection_below_required_rate"
        in status.reason_codes
    )


def test_suite_model_rejects_empty_case_collection() -> None:
    # JSON Schema owns minItems for file loading; the typed model remains usable
    # for programmatic report aggregation tests.
    suite = AssuranceQualificationSuite(
        suite_id="programmatic-empty",
        cases=[],
    )
    assert suite.cases == []
