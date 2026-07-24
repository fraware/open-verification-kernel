"""Tests for typed routing decisions and policy configuration."""

from __future__ import annotations

from pathlib import Path


from ovk.adapters.lane import build_default_lane_registry
from ovk.core.execution_models import (
    AbstractionCoverage,
    ExecutionBudget,
    ExecutionContext,
    MaterialReference,
    RoutingDecision,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
    compute_routing_id,
)
from ovk.core.models import RiskSeverity, VerificationSubject
from ovk.core.policy_config import resolve_routing_config, routing_enforced_for_lane
from ovk.core.router import (
    ROUTER_VERSION,
    RoutingConfig,
    route_intent,
    route_obligation,
    routing_config_from_policy,
    routing_decision_to_legacy_dict,
)
from ovk.core.schema_validation import load_json, validate_against_schema
from ovk.paths import schema_path


def _subject() -> VerificationSubject:
    return VerificationSubject(repo="example/repo", head_sha="abc", base_sha="def")


def _obligation(*, lane: str = "authorization") -> VerificationObligation:
    abstraction = {
        "author_type": "ai_agent",
        "agent": "codex",
        "task": "test",
        "routes": [
            {
                "path": "/admin",
                "admin_only_before": True,
                "admin_only_after": True,
                "reachable_after": [],
            }
        ],
    }
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=_subject(),
        intent_id="no-admin-route-bypass",
        intent_version="0.1.0",
        lane=lane,
        property_kind="access_control",
        severity=RiskSeverity.HIGH,
        compiler_id="test",
        compiler_version="0.1.0",
        materials=[
            MaterialReference(
                material_id="m1",
                kind="diff",
                uri="src/a.py",
                sha256="b" * 64,
                size_bytes=1,
            )
        ],
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=AbstractionCoverage(status="complete", confidence=1.0, extracted_elements=1),
        acceptable_guarantees=[
            "smt_refutation_search",
            "policy_evaluation",
            "workflow_secrets_boundary_check",
            "state_machine_safety",
        ],
        required_capabilities=[],
        policy_digest="policy-digest",
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})


def test_routing_config_defaults_to_shadow() -> None:
    config = routing_config_from_policy({})
    assert config.mode == "shadow"
    assert config.strategy == "primary_with_optional_corroboration"
    assert config.aggregation == "ovk.aggregate.fail_dominant.v1"
    assert config.max_selected_backends == 2
    assert config.prefer_deterministic is False
    assert config.allow_fallback is False
    assert config.resolved_mode() == "shadow"


def test_enforced_without_lanes_resolves_to_shadow() -> None:
    config = routing_config_from_policy({"routing": {"mode": "enforced"}})
    assert config.mode == "enforced"
    assert config.resolved_mode() == "shadow"


def test_route_obligation_selects_primary_and_optional_corroborator() -> None:
    registry = build_default_lane_registry()
    obligation = _obligation(lane="authorization")
    context = ExecutionContext(
        subject=_subject(),
        budget=ExecutionBudget(
            total_wall_time_seconds=60,
            per_backend_wall_time_seconds=30,
            max_memory_mb=512,
            max_parallel_backends=2,
            allow_network=False,
            allow_repository_write=False,
        ),
        policy_digest=obligation.policy_digest,
    )
    decision = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=2),
    )
    assert isinstance(decision, RoutingDecision)
    assert decision.schema_version == "ovk.routing.v1"
    assert len(decision.selected) <= 2
    assert decision.selected
    assert decision.selected[0].required is True
    assert decision.selected[0].backend == "lane-authorization"
    if len(decision.selected) == 2:
        assert decision.selected[1].required is False
    assert decision.routing_id
    expected = compute_routing_id(
        obligation_id=decision.obligation_id,
        requested=decision.requested,
        eligible=decision.eligible,
        selected=decision.selected,
        rejected=decision.rejected,
        aggregation_policy=decision.aggregation_policy,
        fallback_policy=decision.fallback_policy,
        budget=decision.budget,
        policy_digest=decision.policy_digest,
        router_version=ROUTER_VERSION,
        assessments=registry.candidates(obligation, context),
    )
    assert decision.routing_id == expected


def test_route_obligation_deterministic_ordering() -> None:
    registry = build_default_lane_registry()
    obligation = _obligation(lane="ci_secrets")
    context = ExecutionContext(subject=_subject(), policy_digest="p")
    first = route_obligation(obligation, registry, context=context)
    second = route_obligation(obligation, registry, context=context)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_legacy_route_intent_compatibility_dict() -> None:
    from ovk.core.capabilities import CapabilityRegistry

    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = load_json(Path("templates/ci_cd/agent_cannot_disable_own_gate.intent.json"))
    plan = route_intent(intent, registry.all())
    assert isinstance(plan, dict)
    assert "opa" in {item["backend"] for item in plan["selected"]}
    typed = route_intent(intent, registry.all(), as_legacy_dict=False)
    assert isinstance(typed, RoutingDecision)
    legacy = routing_decision_to_legacy_dict(typed, intent_id=intent["intent_id"])
    assert legacy["selected"]


def test_policy_config_enforced_lane_helper() -> None:
    policy = {"routing": {"mode": "shadow", "enforced_lanes": ["authorization"]}}
    assert resolve_routing_config(policy).enforced_lanes == frozenset({"authorization"})
    assert routing_enforced_for_lane(policy, "authorization") is True
    assert routing_enforced_for_lane(policy, "deployment") is False


def test_verification_config_schema_accepts_routing_block() -> None:
    schema = load_json(schema_path("verification.config.schema.json"))
    payload = {
        "schema_version": "ovk.config.v1",
        "mode": "advisory",
        "default_on_unknown": "require_human_review",
        "routing": {
            "mode": "shadow",
            "strategy": "primary_with_optional_corroboration",
            "aggregation": "ovk.aggregate.fail_dominant.v1",
            "max_selected_backends": 2,
            "prefer_deterministic": False,
            "allow_fallback": False,
            "enforced_lanes": ["authorization"],
        },
    }
    report = validate_against_schema(payload, schema)
    assert report.valid, [issue.message for issue in report.issues]
