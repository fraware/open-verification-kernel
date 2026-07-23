"""Authorization vertical-slice enforcement tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.adapters.authorization import build_authorization_registry
from ovk.adapters.authorization.z3_adapter import z3_available
from ovk.core.adapter_runtime import execute_obligations
from ovk.core.authorization_compiler import COMPILER_ID, compile_authorization_obligation
from ovk.core.backend_aggregation import aggregate_fail_dominant_v1
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.execution_models import BackendSelection, ExecutionBudget, ExecutionContext, NormalizedBackendResult
from ovk.core.models import MergeRecommendation, VerificationStatus
from ovk.core.router import RoutingConfig, route_obligation


def _auth_policy(**routing_overrides):
    routing = {
        "mode": "shadow",
        "enforced_lanes": ["authorization"],
        "max_selected_backends": 2,
        "prefer_deterministic": False,
        "allow_fallback": False,
    }
    routing.update(routing_overrides)
    return {"routing": routing, "budget": {}}


def test_neutral_compiler_builds_typed_obligation() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h", base_sha="b")
    assert obligation.compiler_id == COMPILER_ID
    assert obligation.lane == "authorization"
    assert obligation.obligation_id
    assert obligation.coverage.status in {"complete", "partial", "unknown"}


def test_policy_changes_selected_backend_execution() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")

    det_policy = {
        "routing": {"prefer_deterministic": True, "max_selected_backends": 1, "enforced_lanes": ["authorization"]},
        "budget": {"allowed_backends": ["authorization-deterministic"]},
    }
    budget = ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p")
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1, enforced_lanes=frozenset({"authorization"})),
        policy=det_policy,
    )
    assert [item.backend for item in routing.selected] == ["authorization-deterministic"]
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.results[0].backend == "authorization-deterministic"
    assert record.aggregate_status == VerificationStatus.FAIL

    # Deny deterministic; allow only z3-native (may be unavailable).
    z3_budget = budget.model_copy(update={"allowed_backends": ["z3-native"]})
    z3_context = ExecutionContext(subject=obligation.subject, budget=z3_budget, policy_digest="p")
    z3_routing = route_obligation(
        obligation,
        registry,
        context=z3_context,
        config=RoutingConfig(max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["z3-native"]}},
    )
    if z3_available():
        assert z3_routing.selected
        assert z3_routing.selected[0].backend == "z3-native"
        z3_record = BackendControlPlane().execute(obligation, z3_routing, registry=registry)
        assert z3_record.results[0].backend == "z3-native"
    else:
        assert not z3_routing.selected or z3_routing.selected[0].backend != "authorization-deterministic"


def test_enforced_authorization_emits_v2_preview_fields() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence_items = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_auth_policy(prefer_deterministic=True),
    )
    evidence = evidence_items[0]
    assert evidence.routing_enforced is True
    assert evidence.schema_version == "ovk.evidence.v2"
    assert evidence.obligation_id
    assert evidence.routing_id
    assert evidence.selected_backends
    assert evidence.execution_attempts is not None
    assert evidence.decision.get("routing_enforced") is True
    assert evidence.decision.get("merge_recommendation") == "block"


def test_authorization_timeout_yields_review() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = ExecutionBudget(
        total_wall_time_seconds=0,
        per_backend_wall_time_seconds=0,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1, accept_partial_primary=True),
    )
    # Force selection even if budget marks unavailable by rewriting selected list.
    if not routing.selected:
        routing = routing.model_copy(
            update={
                "selected": [
                    BackendSelection(
                        backend="authorization-deterministic",
                        reason="forced-timeout-test",
                        expected_guarantee="deterministic_witness",
                        required=True,
                        score=1.0,
                    )
                ]
            }
        )
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.results[0].status == VerificationStatus.UNKNOWN
    assert record.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW


def test_authorization_disagreement_blocks() -> None:
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=[
            BackendSelection(backend="z3-native", reason="p", expected_guarantee="smt_refutation_search", required=True),
            BackendSelection(
                backend="authorization-deterministic",
                reason="c",
                expected_guarantee="deterministic_witness",
                required=False,
            ),
        ],
        results=[
            NormalizedBackendResult(
                attempt_id="1",
                backend="z3-native",
                status=VerificationStatus.PASS,
                guarantee_type="smt_refutation_search",
            ),
            NormalizedBackendResult(
                attempt_id="2",
                backend="authorization-deterministic",
                status=VerificationStatus.FAIL,
                guarantee_type="deterministic_witness",
            ),
        ],
        acceptable_guarantees=["smt_refutation_search", "deterministic_witness"],
    )
    assert outcome.merge_recommendation == MergeRecommendation.BLOCK
    assert outcome.disagreement is not None


def test_fallback_not_implicit_when_z3_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import ovk.adapters.authorization.z3_adapter as z3_mod

    monkeypatch.setattr(z3_mod, "z3_available", lambda: False)
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["z3-native"],
        denied_backends=["authorization-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(obligation, registry, context=context, config=RoutingConfig(max_selected_backends=1))
    assert all(item.backend != "authorization-deterministic" for item in routing.selected)
    # With only z3 allowed and unavailable, no required execution should allow.
    if routing.selected:
        record = BackendControlPlane().execute(obligation, routing, registry=registry)
        assert record.merge_recommendation != MergeRecommendation.ALLOW
    else:
        assert routing.selected == []
