"""PR6 — single authoritative routing pipeline tests."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.adapter_runtime import execute_obligations
from ovk.core.kernel import execute_kernel
from ovk.core.routing_pipeline import (
    build_authoritative_routing_plan,
    route_compiled_obligation,
    compile_typed_obligation,
)
from ovk.core.router import routing_decision_to_legacy_dict
from ovk.mcp_server import select_backends


def _auth_policy(**routing_overrides):
    routing = {
        "mode": "shadow",
        "enforced_lanes": ["authorization"],
        "max_selected_backends": 1,
        "prefer_deterministic": True,
        "allow_fallback": False,
    }
    routing.update(routing_overrides)
    return {"routing": routing, "budget": {"allowed_backends": ["authorization-deterministic"]}}


def test_compile_before_route_produces_single_routing_id() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligations = [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}]
    plan = build_authoritative_routing_plan(
        obligations,
        policy=_auth_policy(),
        repo="example/repo",
        head_sha="abc",
    )
    assert len(plan.routing_by_intent) == 1
    routing = plan.routing_by_intent["no-admin-route-bypass"]
    assert routing.routing_id
    assert routing.obligation_id == plan.typed_obligations["no-admin-route-bypass"].obligation_id


def test_kernel_mcp_and_evidence_share_routing_id() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    policy = _auth_policy()
    obligations = [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}]
    plan = build_authoritative_routing_plan(
        obligations,
        policy=policy,
        repo="example/repo",
        head_sha="abc",
    )
    expected_routing_id = plan.routing_by_intent["no-admin-route-bypass"].routing_id

    mcp_plan = select_backends(
        "no-admin-route-bypass",
        lane="authorization",
        lane_input=data,
        repo="example/repo",
        head_sha="abc",
        policy=policy,
    )
    assert mcp_plan["routing_id"] == expected_routing_id

    evidence_items = execute_obligations(
        obligations,
        plan.legacy_routing_by_intent(),
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=policy,
    )
    assert evidence_items[0].routing_id == expected_routing_id
    routing_artifacts = [
        artifact for artifact in evidence_items[0].generated_artifacts if artifact.get("kind") == "backend_routing"
    ]
    assert routing_artifacts
    assert routing_artifacts[0]["routing_id"] == expected_routing_id


def test_route_intent_and_route_obligation_diverge_for_legacy_multi_select() -> None:
    """Legacy manifest routing may differ; enforced typed path is authoritative."""
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligation = compile_typed_obligation(
        lane="authorization",
        data=data,
        repo="r",
        head_sha="h",
        policy=_auth_policy(max_selected_backends=1),
    )
    typed = route_compiled_obligation(obligation, lane="authorization", policy=_auth_policy(max_selected_backends=1))
    assert len(typed.selected) == 1
    assert typed.selected[0].backend == "authorization-deterministic"
    legacy_dict = routing_decision_to_legacy_dict(typed, intent_id=obligation.intent_id)
    assert legacy_dict["routing_id"] == typed.routing_id


def test_kernel_uses_authoritative_routing_for_obligations() -> None:
    diff_text = Path("examples/multi_surface/pr_combined.diff").read_text(encoding="utf-8")
    from dataclasses import replace

    from ovk.core.context import build_repository_context

    ctx = build_repository_context(
        changed_files=["src/routes/admin.ts", ".github/workflows/ci.yml", "infra/main.tf"],
        repo="test/repo",
        head_sha="deadbeef",
    )
    ctx = replace(
        ctx,
        policy={
            "routing": {
                "enforced_lanes": ["authorization"],
                "prefer_deterministic": True,
            },
            "budget": {"allowed_backends": ["authorization-deterministic"]},
        },
    )
    result = execute_kernel(
        diff_text=diff_text,
        use_cache=False,
        repo="test/repo",
        head_sha="deadbeef",
        context=ctx,
    )
    auth_evidence = next(
        item for item in result.bundle.evidence if item.intent.get("intent_id") == "no-admin-route-bypass"
    )
    assert auth_evidence.routing_id
    auth_routing = next(
        item
        for item in result.routing
        if item.get("obligation_id") == auth_evidence.obligation_id or item.get("intent_id") == "no-admin-route-bypass"
    )
    assert auth_routing["routing_id"] == auth_evidence.routing_id
