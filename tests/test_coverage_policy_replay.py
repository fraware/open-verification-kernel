"""Coverage-policy replay and zero-result evidence regressions."""

from __future__ import annotations

import copy

from ovk.core.adapter_runtime import execute_obligations
from ovk.core.evidence_integrity import compute_evidence_digest
from ovk.core.evidence_verifier import verify_evidence_semantics
from ovk.core.routing_pipeline import build_authoritative_routing_plan


def _policy(lane: str, *, accept_partial: bool = False) -> dict:
    routing = {
        "mode": "enforced",
        "enforced_lanes": [lane],
        "max_selected_backends": 1,
        "prefer_deterministic": True,
        "allow_fallback": False,
    }
    if accept_partial:
        routing["accept_partial_primary"] = True
    budget = {"allowed_backends": ["authorization-deterministic"]} if lane == "authorization" else {}
    return {"routing": routing, "budget": budget}


def _partial_authorization_input() -> dict:
    source = (
        "from fastapi import Depends, FastAPI\n"
        "def require_admin():\n    return 'admin'\n"
        "app = FastAPI()\n"
        "@app.get('/admin', dependencies=[Depends(require_admin)])\n"
        "def admin():\n    return {}\n"
        "dynamic_path = '/dynamic'\n"
        "@get(dynamic_path)\n"
        "def dynamic():\n    return {}\n"
    )
    return {
        "framework": "fastapi",
        "materials": {
            "path": "app.py",
            "base_source": source,
            "head_source": source,
        },
    }


def _single_instance(plan, obligations: list[dict]) -> str:
    """Resolve the sole obligation instance used by these replay fixtures."""
    assert len(obligations) == 1
    instance_id = plan.instance_key(obligations[0])
    assert instance_id in plan.typed_obligations
    assert instance_id in plan.routing_by_instance
    return instance_id


def test_partial_coverage_requires_explicit_bound_acceptance_for_primary() -> None:
    obligations = [
        {
            "lane": "authorization",
            "intent_id": "no-admin-route-bypass",
            "input": _partial_authorization_input(),
        }
    ]
    default_plan = build_authoritative_routing_plan(
        obligations,
        policy=_policy("authorization"),
        repo="example/repo",
        head_sha="head",
        base_sha="base",
    )
    default_instance = _single_instance(default_plan, obligations)
    default_typed = default_plan.typed_obligations[default_instance]
    assert default_typed.coverage.status == "partial"
    assert not any(item.required for item in default_plan.routing_by_instance[default_instance].selected)

    accepted_plan = build_authoritative_routing_plan(
        obligations,
        policy=_policy("authorization", accept_partial=True),
        repo="example/repo",
        head_sha="head",
        base_sha="base",
    )
    accepted_instance = _single_instance(accepted_plan, obligations)
    accepted_typed = accepted_plan.typed_obligations[accepted_instance]
    assert accepted_typed.coverage.status == "partial"
    assert any(item.required for item in accepted_plan.routing_by_instance[accepted_instance].selected)


def test_nondefault_bound_coverage_policy_replays_through_v3_evidence() -> None:
    evidence = execute_obligations(
        [
            {
                "lane": "authorization",
                "intent_id": "no-admin-route-bypass",
                "input": _partial_authorization_input(),
            }
        ],
        {},
        repo="example/repo",
        head_sha="head",
        base_sha="base",
        use_cache=False,
        parallel=False,
        policy=_policy("authorization", accept_partial=True),
    )[0]

    assert evidence.coverage and evidence.coverage["status"] == "partial"
    assert evidence.decision["decision_state"] == "allow"
    trace = next(
        item
        for item in evidence.generated_artifacts
        if item.get("kind") == "control_plane_trace"
    )
    assert trace["coverage_policy"]["accept_partial_coverage"] is True
    report = verify_evidence_semantics(evidence)
    assert report.valid, report.to_dict()


def test_trace_policy_copy_cannot_override_obligation_bound_policy() -> None:
    evidence = execute_obligations(
        [
            {
                "lane": "authorization",
                "intent_id": "no-admin-route-bypass",
                "input": _partial_authorization_input(),
            }
        ],
        {},
        repo="example/repo",
        head_sha="head",
        base_sha="base",
        use_cache=False,
        parallel=False,
        policy=_policy("authorization", accept_partial=True),
    )[0].model_dump(mode="json")

    tampered = copy.deepcopy(evidence)
    trace = next(
        item
        for item in tampered["generated_artifacts"]
        if item.get("kind") == "control_plane_trace"
    )
    trace["coverage_policy"]["accept_partial_coverage"] = False
    tampered["signature"] = None
    tampered["evidence_digest"] = compute_evidence_digest(tampered)

    report = verify_evidence_semantics(tampered)
    assert not report.valid
    assert any("trace coverage_policy does not match" in issue.message for issue in report.issues)


def test_zero_result_v3_evidence_is_independently_recomputable() -> None:
    evidence = execute_obligations(
        [{"lane": "infrastructure", "input": {"resources": []}}],
        {},
        repo="example/repo",
        head_sha="head",
        use_cache=False,
        parallel=False,
        policy=_policy("infrastructure"),
    )[0]

    assert evidence.executed_backends == []
    assert evidence.backend_claims[0].backend == "none"
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.compiler is not None
    assert evidence.checker_id == evidence.compiler["compiler_id"]
    assert evidence.checker_version == evidence.compiler["compiler_version"]
    report = verify_evidence_semantics(evidence)
    assert report.valid, report.to_dict()
