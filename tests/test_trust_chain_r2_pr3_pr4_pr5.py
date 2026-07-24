"""Adversarial tests for OVK R2 trust-chain PR3–PR5."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ovk.adapters.authorization import build_authorization_registry
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_aggregation import (
    FALLBACK_BLOCKING_TERMINATIONS,
    aggregate_fail_dominant_v1,
    evaluate_fallback_acceptance,
)
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.execution_models import (
    BackendCapabilityAssessment,
    BackendObligation,
    BackendSelection,
    ExecutionAttempt,
    ExecutionBudget,
    ExecutionContext,
    FallbackPolicy,
    NormalizedBackendResult,
    RoutingDecision,
)
from ovk.core.models import MergeRecommendation, VerificationStatus
from ovk.core.router import RoutingConfig, route_obligation, select_primary_with_optional_corroboration
from ovk.core.self_protection_compiler import (
    compile_self_protection_obligation,
    resolve_metadata_trusted,
)


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=2,
        allow_network=False,
        allow_repository_write=False,
    )


def _assessment(
    *,
    backend: str = "test-backend",
    support: str = "supported",
    coverage_requirements_met: bool = True,
    score: float = 0.9,
) -> BackendCapabilityAssessment:
    return BackendCapabilityAssessment(
        backend=backend,
        support=support,  # type: ignore[arg-type]
        score=score,
        guarantee_type="policy_evaluation",
        material_requirements_met=True,
        coverage_requirements_met=coverage_requirements_met,
        native_available=False,
        estimated_wall_time_seconds=5.0,
        estimated_memory_mb=256,
        reasons=["test assessment"],
    )


def test_incomplete_coverage_rejected_as_required_primary() -> None:
    assessments = [_assessment(coverage_requirements_met=False)]
    selected, rejected, eligible = select_primary_with_optional_corroboration(
        assessments,
        acceptable_guarantees=["policy_evaluation"],
        config=RoutingConfig(accept_partial_primary=False),
        budget=_budget(),
    )
    assert selected == []
    assert any(item.reason == "coverage requirements not met" for item in rejected)
    assert eligible == []


def test_incomplete_coverage_eligible_optional_when_policy_allows() -> None:
    assessments = [_assessment(coverage_requirements_met=False)]
    selected, rejected, eligible = select_primary_with_optional_corroboration(
        assessments,
        acceptable_guarantees=["policy_evaluation"],
        config=RoutingConfig(accept_partial_primary=True, max_selected_backends=2),
        budget=_budget(),
    )
    assert not any(item.required for item in selected)
    assert rejected == []
    assert len(eligible) == 1
    assert eligible[0].support == "partial"
    assert "incomplete coverage" in " ".join(eligible[0].reasons)
    if selected:
        assert all(not item.required for item in selected)


def test_guarantee_mismatch_fails_closed_without_rewrite() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = _budget()
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    routing = routing.model_copy(
        update={
            "selected": [
                BackendSelection(
                    backend="authorization-deterministic",
                    reason="test",
                    expected_guarantee="smt_refutation_search",
                    required=True,
                )
            ]
        }
    )

    adapter = registry.require("authorization-deterministic")
    original_compile = adapter.compile

    def _mismatching_compile(
        compiled_obligation: Any,
        compiled_routing: RoutingDecision,
    ) -> BackendObligation:
        compiled = original_compile(compiled_obligation, compiled_routing)
        return compiled.model_copy(update={"expected_guarantee": "deterministic_witness"})

    adapter.compile = _mismatching_compile  # type: ignore[method-assign]

    record = BackendControlPlane(use_hardened_cache=False).execute(
        obligation,
        routing,
        registry=registry,
        cache=None,
    )
    assert record.results[0].status == VerificationStatus.UNKNOWN
    assert record.attempts[0].termination == "invalid_output"
    assert record.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW
    assert "compiler guarantee mismatch" in record.results[0].limits[0]


@pytest.mark.parametrize("termination", sorted(FALLBACK_BLOCKING_TERMINATIONS))
def test_blocking_terminations_never_accept_fallback(termination: str) -> None:
    policy = FallbackPolicy(
        allow_fallback=True,
        fallback_backends=["authorization-deterministic"],
        acceptable_fallback_guarantees=["deterministic_witness"],
    )
    used, accepted, cause = evaluate_fallback_acceptance(
        policy=policy,
        selected=[
            BackendSelection(
                backend="authorization-deterministic",
                reason="test",
                expected_guarantee="smt_refutation_search",
                required=True,
            )
        ],
        attempts=[
            ExecutionAttempt(
                attempt_id="att-1",
                backend_obligation_id="bo-1",
                backend="authorization-deterministic",
                required=True,
                started_at="2026-01-01T00:00:00Z",
                finished_at="2026-01-01T00:00:01Z",
                duration_ms=1.0,
                termination=termination,  # type: ignore[arg-type]
                native_execution=False,
            )
        ],
        results=[
            NormalizedBackendResult(
                attempt_id="att-1",
                backend="authorization-deterministic",
                status=VerificationStatus.PASS,
                guarantee_type="deterministic_witness",
            )
        ],
        acceptable_guarantees=["smt_refutation_search"],
    )
    assert used is True
    assert accepted is False
    assert cause == termination


def test_allow_fallback_without_blocking_cause_can_accept() -> None:
    policy = FallbackPolicy(
        allow_fallback=True,
        fallback_backends=["authorization-deterministic"],
        acceptable_fallback_guarantees=["deterministic_witness"],
    )
    used, accepted, _ = evaluate_fallback_acceptance(
        policy=policy,
        selected=[
            BackendSelection(
                backend="authorization-deterministic",
                reason="test",
                expected_guarantee="smt_refutation_search",
                required=True,
            )
        ],
        attempts=[
            ExecutionAttempt(
                attempt_id="att-1",
                backend_obligation_id="bo-1",
                backend="authorization-deterministic",
                required=True,
                started_at="2026-01-01T00:00:00Z",
                finished_at="2026-01-01T00:00:01Z",
                duration_ms=1.0,
                termination="completed",
                native_execution=False,
            )
        ],
        results=[
            NormalizedBackendResult(
                attempt_id="att-1",
                backend="authorization-deterministic",
                status=VerificationStatus.PASS,
                guarantee_type="deterministic_witness",
            )
        ],
        acceptable_guarantees=["smt_refutation_search"],
    )
    assert used is True
    assert accepted is True


def test_aggregate_fail_dominant_rejects_unaccepted_fallback_pass() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[
            BackendSelection(
                backend="a",
                reason="test",
                expected_guarantee="smt_refutation_search",
                required=True,
            )
        ],
        results=[
            NormalizedBackendResult(
                attempt_id="att-1",
                backend="a",
                status=VerificationStatus.PASS,
                guarantee_type="deterministic_witness",
            )
        ],
        acceptable_guarantees=["smt_refutation_search"],
        fallback_policy=FallbackPolicy(allow_fallback=False),
        attempts=[
            ExecutionAttempt(
                attempt_id="att-1",
                backend_obligation_id="bo-1",
                backend="a",
                required=True,
                started_at="2026-01-01T00:00:00Z",
                finished_at="2026-01-01T00:00:01Z",
                duration_ms=1.0,
                termination="timeout",
                native_execution=False,
            )
        ],
    )
    assert outcome.merge_recommendation == MergeRecommendation.REQUIRE_STRONGER_CHECK
    assert outcome.fallback_used is True
    assert outcome.fallback_accepted is False
    assert outcome.fallback_cause == "timeout"


def test_metadata_trusted_defaults_false() -> None:
    obligation = compile_self_protection_obligation(
        {
            "before": {"required_checks": ["ovk-verify"]},
            "after": {"required_checks": ["ovk-verify"]},
        },
        repo="r",
        head_sha="h",
        base_sha="b",
    )
    assert obligation.abstraction["metadata_trusted"] is False
    branch_materials = [item for item in obligation.materials if item.kind == "branch_protection"]
    assert branch_materials
    assert all(not item.trusted for item in branch_materials)


def test_resolve_metadata_trusted_requires_provenance_kind() -> None:
    assert resolve_metadata_trusted(None) is False
    assert resolve_metadata_trusted({}) is False
    assert resolve_metadata_trusted({"trust": {"metadata_trusted": True}}) is False
    assert (
        resolve_metadata_trusted(
            {
                "trust": {
                    "metadata_trusted": True,
                    "provenance_kind": "protected_base_workflow",
                }
            }
        )
        is True
    )


def test_current_state_only_routing_flag_cannot_authorize_trust() -> None:
    assert (
        resolve_metadata_trusted(
            {
                "routing": {"metadata_trusted": True},
                "trust": {"metadata_trusted": True},
            }
        )
        is False
    )
