"""Trust-boundary regressions for coverage qualification and caller routing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.coverage_contract import qualify_coverage
from ovk.core.routing_pipeline import (
    build_authoritative_routing_plan,
    ensure_authoritative_routing,
)


def _auth_data() -> dict:
    return json.loads(
        Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8")
    )


def _policy() -> dict:
    return {
        "routing": {
            "enforced_lanes": ["authorization"],
            "prefer_deterministic": True,
            "max_selected_backends": 1,
        },
        "budget": {"allowed_backends": ["authorization-deterministic"]},
    }


def test_caller_route_may_attest_canonical_equality_but_not_replace_it() -> None:
    obligations = [
        {"lane": "authorization", "input": _auth_data(), "intent_id": "no-admin-route-bypass"}
    ]
    canonical = build_authoritative_routing_plan(
        obligations, policy=_policy(), repo="r", head_sha="h"
    )
    verified = ensure_authoritative_routing(
        obligations,
        canonical.legacy_routing_by_intent(),
        policy=_policy(),
        repo="r",
        head_sha="h",
    )
    intent = "no-admin-route-bypass"
    assert verified.routing_by_intent[intent].routing_id == canonical.routing_by_intent[intent].routing_id
    assert verified.routing_by_intent[intent].model_dump(mode="json") == canonical.routing_by_intent[intent].model_dump(mode="json")


def test_stale_or_forged_caller_route_is_rejected() -> None:
    obligations = [
        {"lane": "authorization", "input": _auth_data(), "intent_id": "no-admin-route-bypass"}
    ]
    canonical = build_authoritative_routing_plan(
        obligations, policy=_policy(), repo="r", head_sha="h"
    )
    supplied = canonical.legacy_routing_by_intent()
    supplied["no-admin-route-bypass"] = {
        **supplied["no-admin-route-bypass"],
        "routing_id": "forged-routing-id",
    }
    with pytest.raises(RuntimeError, match="stale or non-canonical"):
        ensure_authoritative_routing(
            obligations,
            supplied,
            policy=_policy(),
            repo="r",
            head_sha="h",
        )


def test_enforced_incomplete_coverage_cannot_be_required_primary() -> None:
    # This source-only FastAPI input intentionally lacks the base material needed
    # for complete change coverage.
    head = (
        "from fastapi import Depends, FastAPI\n"
        "def require_admin():\n    return 'admin'\n"
        "app = FastAPI()\n"
        "@app.get('/admin', dependencies=[Depends(require_admin)])\n"
        "def admin():\n    return {}\n"
    )
    data = {"framework": "fastapi", "materials": {"path": "app.py", "head_source": head}}
    obligations = [
        {"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}
    ]
    plan = build_authoritative_routing_plan(
        obligations,
        policy=_policy(),
        repo="r",
        head_sha="h",
    )
    instance_id = plan.instance_key(obligations[0])
    typed = plan.typed_obligations[instance_id]
    assert typed.coverage.status != "complete"
    routing = plan.routing_by_instance[instance_id]
    assert not any(item.required for item in routing.selected)


def test_coverage_contract_separates_execution_from_strict_allow() -> None:
    from ovk.adapters.authorization import build_authorization_registry
    from ovk.core.authorization_compiler import compile_authorization_obligation
    from ovk.core.execution_budget import execution_budget_from_policy
    from ovk.core.execution_models import ExecutionContext

    head = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/admin')\n"
        "def admin(): return {}\n"
    )
    data = {"framework": "fastapi", "materials": {"path": "app.py", "head_source": head}}
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h", policy=_policy())
    registry = build_authorization_registry()
    context = ExecutionContext(
        subject=obligation.subject,
        budget=execution_budget_from_policy(_policy()),
        policy_digest=obligation.policy_digest,
    )
    assessment = next(
        item for item in registry.candidates(obligation, context)
        if item.backend == "authorization-deterministic"
    )
    qualification = qualify_coverage(obligation, assessment, enforced=True)
    assert qualification.can_execute is True
    assert qualification.can_produce_advisory_evidence is True
    assert qualification.can_be_required_primary is False
    assert qualification.can_support_strict_allow is False
