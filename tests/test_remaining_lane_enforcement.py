"""Remaining lane enforcement tests: infrastructure, CI secrets, deployment."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.adapters.ci_secrets import build_ci_secrets_registry
from ovk.adapters.deployment import build_deployment_registry
from ovk.adapters.infrastructure import build_infrastructure_registry
from ovk.core.adapter_runtime import execute_obligations
from ovk.core.backend_aggregation import aggregate_fail_dominant_v1
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.ci_secrets_compiler import COMPILER_ID as CI_SECRETS_COMPILER_ID
from ovk.core.ci_secrets_compiler import compile_ci_secrets_obligation
from ovk.core.deployment_compiler import COMPILER_ID as DEPLOYMENT_COMPILER_ID
from ovk.core.deployment_compiler import compile_deployment_obligation
from ovk.core.execution_models import BackendSelection, ExecutionBudget, ExecutionContext, NormalizedBackendResult
from ovk.core.infrastructure_compiler import COMPILER_ID as INFRA_COMPILER_ID
from ovk.core.infrastructure_compiler import compile_infrastructure_obligation
from ovk.core.models import MergeRecommendation, VerificationStatus
from ovk.core.multi_lane import evaluate_lane
from ovk.core.router import RoutingConfig, route_obligation


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _enforced_policy(*lanes: str, **routing_overrides) -> dict:
    routing = {
        "mode": "enforced",
        "enforced_lanes": list(lanes),
        "max_selected_backends": 1,
        "prefer_deterministic": True,
        "allow_fallback": False,
    }
    routing.update(routing_overrides)
    return {"routing": routing, "budget": {}}


# --- Compilers ---


def test_infrastructure_compiler_builds_typed_obligation() -> None:
    data = _load("examples/infrastructure_exposure/input_public_sensitive_resource.json")
    obligation = compile_infrastructure_obligation(data, repo="r", head_sha="h", base_sha="b")
    assert obligation.compiler_id == INFRA_COMPILER_ID
    assert obligation.lane == "infrastructure"
    assert obligation.coverage.status == "complete"
    assert obligation.acceptable_guarantees == ["exposure_graph_check"]


def test_ci_secrets_compiler_unknown_without_workflows() -> None:
    obligation = compile_ci_secrets_obligation({}, repo="r", head_sha="h")
    assert obligation.compiler_id == CI_SECRETS_COMPILER_ID
    assert obligation.coverage.status == "unknown"


def test_deployment_compiler_partial_without_transitions() -> None:
    obligation = compile_deployment_obligation(
        {"states": ["draft", "deployed"]},
        repo="r",
        head_sha="h",
    )
    # Explicit schema compiler is selected when states/transitions materials exist.
    assert obligation.compiler_id == "ovk.deployment.explicit_schema.v1"
    assert obligation.coverage.status == "partial"
    assert obligation.abstraction.get("source_compiler") == "ovk.deployment.explicit_schema.v1"


# --- Selection controls execution ---


@pytest.mark.parametrize(
    ("lane", "example", "registry_builder", "compiler", "backend_id", "expected_rec"),
    [
        (
            "infrastructure",
            "examples/infrastructure_exposure/input_public_sensitive_resource.json",
            build_infrastructure_registry,
            compile_infrastructure_obligation,
            "infrastructure-deterministic",
            "block",
        ),
        (
            "ci_secrets",
            "examples/ci_secrets/input_secrets_exposed.json",
            build_ci_secrets_registry,
            compile_ci_secrets_obligation,
            "ci-secrets-deterministic",
            "block",
        ),
        (
            "deployment",
            "examples/deployment_state/input_skipped_approval.json",
            build_deployment_registry,
            compile_deployment_obligation,
            "deployment-deterministic",
            "block",
        ),
    ],
)
def test_selection_controls_execution(
    lane,
    example,
    registry_builder,
    compiler,
    backend_id,
    expected_rec,
) -> None:
    data = _load(example)
    registry = registry_builder()
    obligation = compiler(data, repo="r", head_sha="h")
    budget = ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=[backend_id],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1, enforced_lanes=frozenset({lane})),
    )
    assert [item.backend for item in routing.selected] == [backend_id]
    # Eligible set honesty: only the deterministic implementation is registered.
    assert sorted(registry.backend_ids()) == [backend_id]
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.results[0].backend == backend_id
    assert record.merge_recommendation.value == expected_rec


def test_unselected_backend_cannot_affect_decision() -> None:
    """Unselected backend results must not change the aggregation outcome."""
    selected = [
        BackendSelection(
            backend="infrastructure-deterministic",
            reason="selected",
            expected_guarantee="exposure_graph_check",
            required=True,
        )
    ]
    clean = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=selected,
        results=[
            NormalizedBackendResult(
                attempt_id="1",
                backend="infrastructure-deterministic",
                status=VerificationStatus.PASS,
                guarantee_type="exposure_graph_check",
            ),
        ],
        acceptable_guarantees=["exposure_graph_check"],
    )
    assert clean.merge_recommendation == MergeRecommendation.ALLOW

    forged = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=selected,
        results=[
            NormalizedBackendResult(
                attempt_id="1",
                backend="infrastructure-deterministic",
                status=VerificationStatus.PASS,
                guarantee_type="exposure_graph_check",
            ),
            NormalizedBackendResult(
                attempt_id="2",
                backend="forged-opa",
                status=VerificationStatus.FAIL,
                guarantee_type="policy_evaluation",
            ),
        ],
        acceptable_guarantees=["exposure_graph_check"],
    )
    # Aggregation only considers selected backends; forged fail is ignored.
    assert forged.merge_recommendation == MergeRecommendation.ALLOW
    assert forged.status == VerificationStatus.PASS


def test_control_plane_does_not_execute_unselected_backend() -> None:
    data = _load("examples/infrastructure_exposure/input_private_sensitive_resource.json")
    registry = build_infrastructure_registry()
    obligation = compile_infrastructure_obligation(data, repo="r", head_sha="h")
    budget = ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["infrastructure-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1),
    )
    # Rewrite selected to empty — no execution, no allow from unselected evidence.
    empty_routing = routing.model_copy(update={"selected": []})
    record = BackendControlPlane().execute(obligation, empty_routing, registry=registry)
    assert record.results == []
    assert record.merge_recommendation != MergeRecommendation.ALLOW


# --- Shadow vs enforced ---


def test_shadow_keeps_legacy_authoritative_for_infrastructure() -> None:
    data = _load("examples/infrastructure_exposure/input_public_sensitive_resource.json")
    evidence_items = execute_obligations(
        [{"lane": "infrastructure", "input": data}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy={"routing": {"mode": "shadow", "enforced_lanes": []}},
    )
    evidence = evidence_items[0]
    assert evidence.routing_enforced is not True
    assert evidence.decision.get("merge_recommendation") == "block"
    shadow = next(
        (item for item in evidence.generated_artifacts if item.get("kind") == "shadow_comparison"),
        None,
    )
    assert shadow is not None
    assert shadow.get("legacy_authoritative") is True


def test_enforced_infrastructure_blocks_public_sensitive() -> None:
    data = _load("examples/infrastructure_exposure/input_public_sensitive_resource.json")
    evidence_items = execute_obligations(
        [{"lane": "infrastructure", "input": data, "intent_id": "no-public-sensitive-resource"}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_enforced_policy("infrastructure"),
    )
    evidence = evidence_items[0]
    assert evidence.routing_enforced is True
    assert evidence.schema_version == "ovk.evidence.v2"
    assert evidence.decision.get("merge_recommendation") == "block"
    assert "infrastructure-deterministic" in (evidence.selected_backends or [])


def test_enforced_ci_secrets_blocks_exposure() -> None:
    data = _load("examples/ci_secrets/input_secrets_exposed.json")
    evidence_items = execute_obligations(
        [{"lane": "ci_secrets", "input": data}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_enforced_policy("ci_secrets"),
    )
    evidence = evidence_items[0]
    assert evidence.routing_enforced is True
    assert evidence.decision.get("merge_recommendation") == "block"
    assert "ci-secrets-deterministic" in (evidence.selected_backends or [])


def test_enforced_deployment_blocks_skipped_approval() -> None:
    data = _load("examples/deployment_state/input_skipped_approval.json")
    evidence_items = execute_obligations(
        [{"lane": "deployment", "input": data}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_enforced_policy("deployment"),
    )
    evidence = evidence_items[0]
    assert evidence.routing_enforced is True
    assert evidence.decision.get("merge_recommendation") == "block"
    assert "deployment-deterministic" in (evidence.selected_backends or [])


def test_enforced_pass_cases() -> None:
    cases = [
        (
            "infrastructure",
            "examples/infrastructure_exposure/input_private_sensitive_resource.json",
            "infrastructure-deterministic",
        ),
        ("ci_secrets", "examples/ci_secrets/input_secrets_safe.json", "ci-secrets-deterministic"),
        (
            "deployment",
            "examples/deployment_state/input_valid_approval_path.json",
            "deployment-deterministic",
        ),
    ]
    for lane, path, backend in cases:
        data = _load(path)
        evidence = execute_obligations(
            [{"lane": lane, "input": data}],
            {},
            repo="example/repo",
            head_sha="abc",
            use_cache=False,
            policy=_enforced_policy(lane),
        )[0]
        assert evidence.routing_enforced is True
        assert evidence.decision.get("merge_recommendation") == "allow"
        assert backend in (evidence.selected_backends or [])


def test_malformed_infrastructure_is_review_not_allow() -> None:
    evidence = execute_obligations(
        [{"lane": "infrastructure", "input": {"resources": []}}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_enforced_policy("infrastructure"),
    )[0]
    assert evidence.decision.get("merge_recommendation") != "allow"


def test_timeout_yields_review_for_deployment() -> None:
    data = _load("examples/deployment_state/input_valid_approval_path.json")
    registry = build_deployment_registry()
    obligation = compile_deployment_obligation(data, repo="r", head_sha="h")
    budget = ExecutionBudget(
        total_wall_time_seconds=0,
        per_backend_wall_time_seconds=0,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["deployment-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1, accept_partial_primary=True),
    )
    if not routing.selected:
        routing = routing.model_copy(
            update={
                "selected": [
                    BackendSelection(
                        backend="deployment-deterministic",
                        reason="forced-timeout-test",
                        expected_guarantee="approval_state_reachability_check",
                        required=True,
                        score=1.0,
                    )
                ]
            }
        )
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.results[0].status == VerificationStatus.UNKNOWN
    assert record.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW


def test_evaluate_lane_compatibility_still_works() -> None:
    """Compatibility API remains available; enforced mode does not remove it."""
    data = _load("examples/infrastructure_exposure/input_public_sensitive_resource.json")
    evidence = evaluate_lane("infrastructure", data, repo="r", head_sha="h")
    assert evidence.decision.get("merge_recommendation") == "block"


def test_denied_backend_does_not_implicitly_fallback() -> None:
    data = _load("examples/ci_secrets/input_secrets_exposed.json")
    registry = build_ci_secrets_registry()
    obligation = compile_ci_secrets_obligation(data, repo="r", head_sha="h")
    budget = ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["nonexistent-opa"],
        denied_backends=["ci-secrets-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1, allow_fallback=False),
    )
    assert all(item.backend != "ci-secrets-deterministic" for item in routing.selected)
    if routing.selected:
        record = BackendControlPlane().execute(obligation, routing, registry=registry)
        assert record.merge_recommendation != MergeRecommendation.ALLOW
    else:
        assert routing.selected == []
