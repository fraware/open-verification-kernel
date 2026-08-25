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
    assert evidence[0].routing_id == plan.routing_by_intent["no-admin-route-bypass"].routing_id


def test_forged_obligation_binding_is_rejected_before_execution() -> None:
    obligations, plan = _inputs()
    intent_id = "no-admin-route-bypass"
    forged = plan.routing_by_intent[intent_id].model_copy(update={"obligation_id": "forged"})
    forged_plan = AuthoritativeRoutingPlan(
        typed_obligations=dict(plan.typed_obligations),
        routing_by_intent={intent_id: forged},
    )
    with pytest.raises(AuthoritativePlanError, match="obligation_id mismatch"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )


def test_forged_policy_binding_is_rejected_before_execution() -> None:
    obligations, plan = _inputs()
    intent_id = "no-admin-route-bypass"
    forged = plan.routing_by_intent[intent_id].model_copy(update={"policy_digest": "forged-policy"})
    forged_plan = AuthoritativeRoutingPlan(
        typed_obligations=dict(plan.typed_obligations),
        routing_by_intent={intent_id: forged},
    )
    with pytest.raises(AuthoritativePlanError, match="policy_digest mismatch"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )


def test_selected_backend_must_be_eligible_and_requested() -> None:
    obligations, plan = _inputs()
    intent_id = "no-admin-route-bypass"
    original = plan.routing_by_intent[intent_id]
    selected = original.selected[0].model_copy(update={"backend": "forged-backend"})
    forged = original.model_copy(update={"selected": [selected]})
    forged_plan = AuthoritativeRoutingPlan(
        typed_obligations=dict(plan.typed_obligations),
        routing_by_intent={intent_id: forged},
    )
    with pytest.raises(AuthoritativePlanError, match="was not requested|was not eligible"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )


def test_selected_guarantee_must_match_eligible_candidate() -> None:
    obligations, plan = _inputs()
    intent_id = "no-admin-route-bypass"
    original = plan.routing_by_intent[intent_id]
    selected = original.selected[0].model_copy(update={"expected_guarantee": "forged-guarantee"})
    forged = original.model_copy(update={"selected": [selected]})
    forged_plan = AuthoritativeRoutingPlan(
        typed_obligations=dict(plan.typed_obligations),
        routing_by_intent={intent_id: forged},
    )
    with pytest.raises(AuthoritativePlanError, match="selected guarantee mismatch"):
        validate_authoritative_plan(
            obligations,
            forged_plan,
            repo="example/repo",
            head_sha="abc",
        )
