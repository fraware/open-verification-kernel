"""Tests for fail-dominant aggregation and shadow control-plane execution."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.lane import build_default_lane_registry
from ovk.core.adapter_runtime import execute_obligations
from ovk.core.backend_aggregation import (
    AGGREGATION_FAIL_DOMINANT_V1,
    aggregate_fail_dominant_v1,
    build_disagreement_artifact,
)
from ovk.core.backend_control_plane import BackendControlPlane, compare_shadow_to_legacy
from ovk.core.execution_models import (
    BackendSelection,
    ExecutionContext,
    NormalizedBackendResult,
)
from ovk.core.models import MergeRecommendation, VerificationStatus
from ovk.core.router import RoutingConfig, route_obligation
from ovk.core.shadow_obligation import build_shadow_obligation


def _result(
    backend: str, status: VerificationStatus, *, guarantee: str = "smt_refutation_search"
) -> NormalizedBackendResult:
    return NormalizedBackendResult(
        attempt_id=f"att-{backend}",
        backend=backend,
        status=status,
        guarantee_type=guarantee,
    )


def test_aggregation_any_required_fail_blocks() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[
            BackendSelection(backend="a", reason="p", expected_guarantee="g", required=True),
            BackendSelection(backend="b", reason="c", expected_guarantee="g", required=False),
        ],
        results=[
            _result("a", VerificationStatus.FAIL),
            _result("b", VerificationStatus.PASS),
        ],
    )
    assert outcome.merge_recommendation == MergeRecommendation.BLOCK
    assert outcome.disagreement is not None
    assert outcome.disagreement["kind"] == "backend_disagreement"


def test_aggregation_optional_fail_blocks_even_if_required_pass() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[
            BackendSelection(backend="a", reason="p", expected_guarantee="g", required=True),
            BackendSelection(backend="b", reason="c", expected_guarantee="g", required=False),
        ],
        results=[
            _result("a", VerificationStatus.PASS),
            _result("b", VerificationStatus.FAIL),
        ],
    )
    assert outcome.merge_recommendation == MergeRecommendation.BLOCK


def test_aggregation_required_unknown_needs_review() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[BackendSelection(backend="a", reason="p", expected_guarantee="g", required=True)],
        results=[_result("a", VerificationStatus.UNKNOWN)],
    )
    assert outcome.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW


def test_aggregation_all_required_pass_allows() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[BackendSelection(backend="a", reason="p", expected_guarantee="smt_refutation_search", required=True)],
        results=[_result("a", VerificationStatus.PASS)],
        acceptable_guarantees=["smt_refutation_search"],
    )
    assert outcome.merge_recommendation == MergeRecommendation.ALLOW
    assert outcome.status == VerificationStatus.PASS


def test_aggregation_missing_required_execution_quality_error() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[BackendSelection(backend="a", reason="p", expected_guarantee="g", required=True)],
        results=[],
    )
    assert outcome.quality_error is True
    assert outcome.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW


def test_disagreement_artifact_shape() -> None:
    artifact = build_disagreement_artifact(
        obligation_id="obl-1",
        results=[
            _result("z3-native", VerificationStatus.PASS),
            _result("authorization-deterministic", VerificationStatus.FAIL),
        ],
        resolution="block",
    )
    assert artifact["policy"] == AGGREGATION_FAIL_DOMINANT_V1
    assert artifact["results"][0]["backend"] == "authorization-deterministic"


def test_control_plane_executes_selected_authorization_backend() -> None:
    registry = build_default_lane_registry()
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligation = build_shadow_obligation(
        lane="authorization",
        data=data,
        repo="example/repo",
        head_sha="abc",
        base_sha="def",
        intent_id="no-admin-route-bypass",
    )
    context = ExecutionContext(subject=obligation.subject, policy_digest=obligation.policy_digest)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1),
    )
    assert routing.selected
    assert routing.selected[0].backend == "lane-authorization"
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.attempts
    assert record.results
    assert record.aggregate_status in {
        VerificationStatus.PASS,
        VerificationStatus.FAIL,
        VerificationStatus.UNKNOWN,
        VerificationStatus.ERROR,
    }
    assert record.routing.routing_id == routing.routing_id


def test_control_plane_isolates_missing_backend_as_error() -> None:
    registry = build_default_lane_registry()
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    obligation = build_shadow_obligation(
        lane="authorization",
        data=data,
        repo="example/repo",
        head_sha="abc",
        base_sha=None,
        intent_id="no-admin-route-bypass",
    )
    context = ExecutionContext(subject=obligation.subject, policy_digest=obligation.policy_digest)
    routing = route_obligation(obligation, registry, context=context, config=RoutingConfig())
    # Force a selected backend that is not registered.
    from ovk.core.execution_models import compute_routing_id
    from ovk.core.router import ROUTER_VERSION

    broken_selected = [
        BackendSelection(
            backend="not-registered-backend",
            reason="forced",
            expected_guarantee="smt_refutation_search",
            required=True,
            score=1.0,
        )
    ]
    routing = routing.model_copy(
        update={
            "selected": broken_selected,
            "routing_id": compute_routing_id(
                obligation_id=routing.obligation_id,
                requested=routing.requested,
                eligible=routing.eligible,
                selected=broken_selected,
                rejected=routing.rejected,
                aggregation_policy=routing.aggregation_policy,
                fallback_policy=routing.fallback_policy,
                budget=routing.budget,
                policy_digest=routing.policy_digest,
                router_version=ROUTER_VERSION,
            ),
        }
    )
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.results[0].status == VerificationStatus.ERROR
    assert record.attempts[0].termination == "tool_error"


def test_shadow_mode_keeps_legacy_authoritative() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence_items = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="example/repo",
        head_sha="deadbeef",
        use_cache=False,
        parallel=False,
        policy={"routing": {"mode": "shadow"}},
    )
    assert len(evidence_items) == 1
    evidence = evidence_items[0]
    assert evidence.decision.get("merge_recommendation") == "block"
    comparisons = [a for a in evidence.generated_artifacts if a.get("kind") == "shadow_comparison"]
    assert comparisons
    comparison = comparisons[0]
    assert comparison["legacy_authoritative"] is True
    assert comparison["legacy"]["authoritative"] is True
    assert comparison["shadow"]["authoritative"] is False


def test_compare_shadow_helper() -> None:
    registry = build_default_lane_registry()
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    obligation = build_shadow_obligation(
        lane="authorization",
        data=data,
        repo="example/repo",
        head_sha="abc",
        base_sha=None,
        intent_id="no-admin-route-bypass",
    )
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, policy_digest=obligation.policy_digest),
    )
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    comparison = compare_shadow_to_legacy(
        shadow=record,
        legacy_status=record.aggregate_status.value,
        legacy_recommendation=record.merge_recommendation.value,
    )
    assert comparison["agreement"] is True
