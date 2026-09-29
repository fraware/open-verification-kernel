from __future__ import annotations

from pathlib import Path

from ovk.core.external_candidate_registry import (
    ExternalAssuranceCandidate,
    ExternalCandidateRegistry,
    load_external_candidate_registry,
    summarize_external_candidate_coverage,
)


REGISTRY_PATH = Path(
    "benchmarks/assurance_qualification/external_candidates.v1.json"
)


def test_committed_external_candidate_registry_is_valid_and_honest() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)
    summary = summarize_external_candidate_coverage(registry)

    assert summary.candidates_total == 2
    assert summary.evaluable_semantic_candidates == 1
    assert summary.supported_now == 0
    assert summary.unsupported_semantics == 1
    assert summary.requires_new_guarantee_family == 0
    assert summary.insufficient_public_evidence == 1
    assert summary.qualification_eligible_candidates == 0
    assert summary.representational_coverage_rate == 0.0
    assert summary.qualification_ready_rate == 0.0

    by_id = {item.candidate_id: item for item in registry.candidates}
    aegra = by_id["aegra-cross-user-run-injection-2026"]
    assert aegra.triage_status == "unsupported_semantics"
    assert aegra.base_sha is not None
    assert aegra.head_sha is not None
    assert aegra.qualification_eligible is False

    chroma = by_id["chroma-python-cross-tenant-idor-2026"]
    assert chroma.triage_status == "insufficient_public_evidence"
    assert chroma.base_sha is None
    assert chroma.head_sha is None


def test_unsupported_candidate_cannot_be_marked_qualification_eligible() -> None:
    try:
        ExternalAssuranceCandidate(
            candidate_id="bad",
            repository="external/repo",
            framework="FastAPI",
            security_property="Owner-only mutation",
            triage_status="unsupported_semantics",
            semantic_pattern="direct_ownership_check",
            reason_codes=["unsupported"],
            references=["https://example.invalid/issue"],
            qualification_eligible=True,
        )
    except ValueError as error:
        assert "only supported_now candidates" in str(error)
    else:
        raise AssertionError("unsupported candidate was marked qualification eligible")


def test_supported_candidate_requires_pinned_transition() -> None:
    try:
        ExternalAssuranceCandidate(
            candidate_id="bad-supported",
            repository="external/repo",
            framework="FastAPI",
            security_property="Owner-only mutation",
            triage_status="supported_now",
            semantic_pattern="supported_pattern",
            reason_codes=["supported"],
            references=["https://example.invalid/issue"],
            qualification_eligible=False,
        )
    except ValueError as error:
        assert "pinned base/head revisions" in str(error)
    else:
        raise AssertionError("supported candidate lacked pinned revisions")


def test_summary_keeps_new_guarantee_family_in_semantic_denominator() -> None:
    registry = ExternalCandidateRegistry(
        registry_id="programmatic",
        reviewed_against={
            "protected_effect_profile_type": "fastapi_dependency_effects_v1",
            "guarantee_type": "protected_effect_integrity_v1",
            "ovk_revision": None,
        },
        candidates=[
            ExternalAssuranceCandidate(
                candidate_id="supported",
                repository="a/repo",
                framework="FastAPI",
                security_property="Property A",
                triage_status="supported_now",
                semantic_pattern="pattern-a",
                reason_codes=["supported"],
                references=["https://example.invalid/a"],
                base_sha="a" * 40,
                head_sha="b" * 40,
            ),
            ExternalAssuranceCandidate(
                candidate_id="new-family",
                repository="b/repo",
                framework="FastAPI",
                security_property="Property B",
                triage_status="requires_new_guarantee_family",
                semantic_pattern="information_flow",
                reason_codes=["outside_current_guarantee_family"],
                references=["https://example.invalid/b"],
            ),
            ExternalAssuranceCandidate(
                candidate_id="insufficient",
                repository="c/repo",
                framework="FastAPI",
                security_property="Property C",
                triage_status="insufficient_public_evidence",
                semantic_pattern="unknown",
                reason_codes=["no_fixed_revision"],
                references=["https://example.invalid/c"],
            ),
        ],
    )

    summary = summarize_external_candidate_coverage(registry)
    assert summary.evaluable_semantic_candidates == 2
    assert summary.representational_coverage_rate == 0.5
