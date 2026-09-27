from __future__ import annotations

from pathlib import Path

from ovk.core.external_candidate_registry import (
    load_external_candidate_registry,
    summarize_external_candidate_coverage,
)


REGISTRY_PATH = Path(
    "benchmarks/assurance_qualification/"
    "external_candidates.heldout_route_mediation.v1.json"
)
REVIEWED_OVK_REVISION = "af94ae1bac88b15a0db1434727f8401e6922a548"


def test_heldout_route_mediation_cohort_is_frozen_before_replay() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)
    summary = summarize_external_candidate_coverage(registry)

    assert registry.reviewed_against["ovk_revision"] == REVIEWED_OVK_REVISION
    assert summary.candidates_total == 3
    assert summary.evaluable_semantic_candidates == 3
    assert summary.supported_now == 1
    assert summary.unsupported_semantics == 2
    assert summary.requires_new_guarantee_family == 0
    assert summary.insufficient_public_evidence == 0
    assert summary.qualification_eligible_candidates == 1
    assert summary.representational_coverage_rate == 1 / 3
    assert summary.qualification_ready_rate == 1 / 3


def test_heldout_cohort_preserves_pre_replay_triage() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)
    by_id = {item.candidate_id: item for item in registry.candidates}

    langflow = by_id["langflow-monitor-missing-route-auth-2026"]
    assert langflow.triage_status == "supported_now"
    assert langflow.qualification_eligible is True

    mlflow = by_id["mlflow-fastapi-permission-middleware-gap-2026"]
    assert mlflow.triage_status == "unsupported_semantics"
    assert mlflow.qualification_eligible is False

    memory = by_id["mcp-memory-documents-missing-auth-2026"]
    assert memory.triage_status == "unsupported_semantics"
    assert memory.qualification_eligible is False


def test_heldout_cohort_uses_exact_pinned_external_transitions() -> None:
    registry = load_external_candidate_registry(REGISTRY_PATH)

    for candidate in registry.candidates:
        assert candidate.base_sha is not None
        assert candidate.head_sha is not None
        assert len(candidate.base_sha) == 40
        assert len(candidate.head_sha) == 40
        assert candidate.base_sha != candidate.head_sha
