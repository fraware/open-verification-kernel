"""End-to-end invariants for the sealed authoritative routing plan."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.authoritative_runtime import (
    AuthoritativePlanError,
    execute_authoritative_plan,
    validate_authoritative_plan,
)
from ovk.core.routing_pipeline import AuthoritativeRoutingPlan, build_authoritative_routing_plan


def _auth_policy() -> dict:
    return {
        "routing": {
            "mode": "shadow",
            "enforced_lanes": ["authorization"],
            "max_selected_backends": 1,
            "prefer_deterministic": True,
            "allow_fallback": False,
        },
        "budget": {"allowed_backends": ["authorization-deterministic"]},
    }


def _inputs() -> tuple[list[dict], AuthoritativeRoutingPlan]:
    data = json.loads(
        Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8")
    )
    obligations = [
        {"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}
    ]
    plan = build_authoritative_routing_plan(
        obligations,
        policy=_auth_policy(),
        repo="example/repo",
        head_sha="abc",
    )
    return obligations, plan


def _single_instance(obligations: list[dict], plan: AuthoritativeRoutingPlan) -> str:
    """Return the instance identity for this fixture without falling back to intent identity."""
    assert len(obligations) == 1
    instance_id = plan.instance_key(obligations[0])
    assert instance_id in plan.routing_by_instance
    return instance_id


def _plan_with_route(
    plan: AuthoritativeRoutingPlan,
    *,
    instance_id: str,
    route,
) -> AuthoritativeRoutingPlan:
    """Replace one route while preserving the plan's per-instance and intent bindings."""
    routes = dict(plan.routing_by_instance)
    routes[instance_id] = route
    return AuthoritativeRoutingPlan(
        typed_obligations=dict(plan.typed_obligations),
        routing_by_instance=routes,
        intent_by_instance=dict(plan.intent_by_instance),
    )


def test_execution_consumes_existing_plan_without_rerouting(monkeypatch: pytest.MonkeyPatch) -> None:
    import ovk.core.routing_pipeline as routing_pipeline

    calls = 0
    original = routing_pipeline.route_compiled_obligation

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(routing_pipeline, "route_compiled_obligation", counted)
    obligations, plan = _inputs()
    instance_id = _single_instance(obligations, plan)
    assert calls == 1

    evidence = execute_authoritative_plan(
        obligations,
        plan,
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        parallel=False,
        policy=_auth_policy(),
    )
    assert calls == 1, "execution must consume the sealed plan, not route again"
    assert evidence[0].routing_id == plan.routing_by_instance[instance_id].routing_id


def test_forged_obligation_binding_is_rejected_before_execution() -> None:
    obligations, plan = _inputs()
    instance_id = _single_instance(obligations, plan)
    forged = plan.routing_by_instance[instance_id].model_copy(update={"obligation_id": "forged"})
    forged_plan = _plan_with_route(plan, instance_id=instance_id, route=forged)
    with pytest.raises(AuthoritativePlanError, match="obligation_id mismatch"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )


def test_forged_policy_binding_is_rejected_before_execution() -> None:
    obligations, plan = _inputs()
    instance_id = _single_instance(obligations, plan)
    forged = plan.routing_by_instance[instance_id].model_copy(update={"policy_digest": "forged-policy"})
    forged_plan = _plan_with_route(plan, instance_id=instance_id, route=forged)
    with pytest.raises(AuthoritativePlanError, match="policy_digest mismatch"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )


def test_selected_backend_must_be_eligible_and_requested() -> None:
    obligations, plan = _inputs()
    instance_id = _single_instance(obligations, plan)
    original = plan.routing_by_instance[instance_id]
    selected = original.selected[0].model_copy(update={"backend": "forged-backend"})
    forged = original.model_copy(update={"selected": [selected]})
    forged_plan = _plan_with_route(plan, instance_id=instance_id, route=forged)
    with pytest.raises(AuthoritativePlanError, match="was not requested|was not eligible"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )


def test_selected_guarantee_must_match_eligible_candidate() -> None:
    obligations, plan = _inputs()
    instance_id = _single_instance(obligations, plan)
    original = plan.routing_by_instance[instance_id]
    selected = original.selected[0].model_copy(update={"expected_guarantee": "forged-guarantee"})
    forged = original.model_copy(update={"selected": [selected]})
    forged_plan = _plan_with_route(plan, instance_id=instance_id, route=forged)
    with pytest.raises(AuthoritativePlanError, match="selected guarantee mismatch"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )
