from __future__ import annotations

from pathlib import Path

from ovk.core.external_candidate_registry import (
    load_external_candidate_registry,
    summarize_external_candidate_coverage,
)


REGISTRY_PATH = Path(
    "benchmarks/assurance_qualification/"
    "external_candidates.round2.v1.json"
)
REVIEWED_OVK_REVISION = "7f6d38d103625f4d33d8942e4b0b10565a6af3e1"


def test_round2_registry_is_frozen_against_preimplementation_revision() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)
    summary = summarize_external_candidate_coverage(registry)

    assert registry.reviewed_against["ovk_revision"] == REVIEWED_OVK_REVISION
    assert summary.candidates_total == 6
    assert summary.evaluable_semantic_candidates == 5
    assert summary.supported_now == 0
    assert summary.unsupported_semantics == 3
    assert summary.requires_new_guarantee_family == 2
    assert summary.insufficient_public_evidence == 1
    assert summary.qualification_eligible_candidates == 0
    assert summary.representational_coverage_rate == 0.0
    assert summary.qualification_ready_rate == 0.0


def test_round2_preserves_incompatible_cases_in_denominator() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)
    by_id = {item.candidate_id: item for item in registry.candidates}

    expected = {
        "airflow-backfill-parser-authorization-conflict-2026": (
            "unsupported_semantics"
        ),
        "open-webui-client-controlled-model-access-bypass-2026": (
            "unsupported_semantics"
        ),
        "flyto-core-mcp-missing-route-authentication-2026": (
            "unsupported_semantics"
        ),
        "fastapi-users-oauth-state-session-binding-2025": (
            "requires_new_guarantee_family"
        ),
        "fastapi-sso-oauth-state-session-binding-2025": (
            "requires_new_guarantee_family"
        ),
        "mlflow-fastapi-jobs-missing-authentication-2026": (
            "insufficient_public_evidence"
        ),
    }

    assert set(by_id) == set(expected)
    for candidate_id, status in expected.items():
        candidate = by_id[candidate_id]
        assert candidate.triage_status == status
        assert candidate.qualification_eligible is False


def test_round2_semantically_classified_transitions_are_pinned() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)

    for candidate in registry.candidates:
        if candidate.triage_status == "insufficient_public_evidence":
            continue
        assert candidate.base_sha is not None
        assert candidate.head_sha is not None
        assert len(candidate.base_sha) == 40
        assert len(candidate.head_sha) == 40
