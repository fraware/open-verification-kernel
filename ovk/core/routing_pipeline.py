"""Single authoritative routing pipeline for typed obligations.

Compiles backend-neutral obligations before routing, routes each obligation
exactly once via ``route_obligation``, and exposes the same ``routing_id`` to
kernel, CLI, MCP, and evidence emitters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ovk.adapters.authorization import build_authorization_registry
from ovk.adapters.ci_secrets import build_ci_secrets_registry
from ovk.adapters.deployment import build_deployment_registry
from ovk.adapters.infrastructure import build_infrastructure_registry
from ovk.adapters.self_protection import build_self_protection_registry
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_registry import BackendRegistry
from ovk.core.ci_secrets_compiler import compile_ci_secrets_obligation
from ovk.core.deployment_compiler import compile_deployment_obligation
from ovk.core.execution_budget import execution_budget_from_policy
from ovk.core.execution_models import ExecutionContext, RoutingDecision, VerificationObligation
from ovk.core.infrastructure_compiler import compile_infrastructure_obligation
from ovk.core.policy_config import routing_enforced_for_lane
from ovk.core.router import RoutingConfig, route_obligation, routing_config_from_policy, routing_decision_to_legacy_dict
from ovk.core.self_protection_compiler import compile_self_protection_obligation, resolve_metadata_trusted

LANE_TO_INTENT = {
    "self_protection": "agent-cannot-disable-own-ci-gate",
    "authorization": "no-admin-route-bypass",
    "infrastructure": "no-public-sensitive-resource",
    "ci_secrets": "no-secrets-in-untrusted-context",
    "deployment": "no-skipped-approval-state",
}


def intent_id_for_obligation(obligation: dict[str, Any]) -> str:
    """Resolve the canonical intent id for a lane obligation dict."""
    lane = str(obligation["lane"])
    return str(obligation.get("intent_id") or LANE_TO_INTENT.get(lane, lane))

RegistryBuilder = Callable[[], BackendRegistry]
CompilerFn = Callable[..., VerificationObligation]

_LANE_REGISTRY: dict[str, RegistryBuilder] = {
    "authorization": build_authorization_registry,
    "self_protection": build_self_protection_registry,
    "infrastructure": build_infrastructure_registry,
    "ci_secrets": build_ci_secrets_registry,
    "deployment": build_deployment_registry,
}


def _compile_authorization(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationObligation:
    return compile_authorization_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
    )


def _compile_self_protection(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationObligation:
    return compile_self_protection_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        metadata_trusted=resolve_metadata_trusted(policy),
    )


def _compile_infrastructure(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationObligation:
    return compile_infrastructure_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
    )


def _compile_ci_secrets(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationObligation:
    return compile_ci_secrets_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
    )


def _compile_deployment(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationObligation:
    return compile_deployment_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
    )


_LANE_COMPILERS: dict[str, CompilerFn] = {
    "authorization": _compile_authorization,
    "self_protection": _compile_self_protection,
    "infrastructure": _compile_infrastructure,
    "ci_secrets": _compile_ci_secrets,
    "deployment": _compile_deployment,
}


@dataclass(frozen=True)
class AuthoritativeRoutingPlan:
    """Typed obligations and immutable routing decisions keyed by intent_id."""

    typed_obligations: dict[str, VerificationObligation]
    routing_by_intent: dict[str, RoutingDecision]

    def routing_metadata_list(self) -> list[dict[str, Any]]:
        return [
            routing_decision_to_legacy_dict(decision, intent_id=intent_id)
            for intent_id, decision in sorted(self.routing_by_intent.items())
        ]

    def legacy_routing_by_intent(self) -> dict[str, dict[str, Any]]:
        return {
            intent_id: routing_decision_to_legacy_dict(decision, intent_id=intent_id)
            for intent_id, decision in self.routing_by_intent.items()
        }


def compile_typed_obligation(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy: dict[str, Any] | None = None,
) -> VerificationObligation:
    """Compile one lane input into a backend-neutral obligation."""
    compiler = _LANE_COMPILERS.get(lane)
    if compiler is None:
        raise ValueError(f"no typed compiler registered for lane {lane!r}")
    return compiler(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
    )


def route_compiled_obligation(
    obligation: VerificationObligation,
    *,
    lane: str,
    policy: dict[str, Any] | None = None,
) -> RoutingDecision:
    """Route a compiled obligation exactly once through ``route_obligation``."""
    registry_builder = _LANE_REGISTRY.get(lane)
    if registry_builder is None:
        raise ValueError(f"no registry registered for lane {lane!r}")
    registry = registry_builder()
    routing_config = routing_config_from_policy(policy)
    budget = execution_budget_from_policy(policy)
    enforced = routing_enforced_for_lane(policy, lane)
    context = ExecutionContext(
        subject=obligation.subject,
        budget=budget,
        policy_digest=obligation.policy_digest,
        metadata={"enforced": enforced, "lane": lane},
    )
    config = RoutingConfig(
        mode="enforced" if enforced else routing_config.mode,
        strategy=routing_config.strategy,
        aggregation=routing_config.aggregation,
        max_selected_backends=routing_config.max_selected_backends,
        prefer_deterministic=routing_config.prefer_deterministic,
        allow_fallback=routing_config.allow_fallback,
        accept_partial_primary=routing_config.accept_partial_primary,
        enforced_lanes=frozenset({lane}) if enforced else routing_config.enforced_lanes,
    )
    return route_obligation(
        obligation,
        registry,
        context=context,
        config=config,
        policy=policy,
    )


def build_authoritative_routing_plan(
    obligations: list[dict[str, Any]],
    *,
    policy: dict[str, Any] | None = None,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
) -> AuthoritativeRoutingPlan:
    """Compile obligations before routing; route each obligation exactly once.

    Experimental lanes without a typed compiler (for example ``backend``/CBMC)
    are skipped here rather than crashing the production control plane. Those
    obligations remain available to legacy evaluators when present.
    """
    typed: dict[str, VerificationObligation] = {}
    routing: dict[str, RoutingDecision] = {}
    for item in obligations:
        lane = str(item["lane"])
        if lane not in _LANE_COMPILERS or lane not in _LANE_REGISTRY:
            # Fail closed for unknown *production* claims elsewhere; skip
            # catalog/experimental lanes that lack typed compilers.
            continue
        intent_id = intent_id_for_obligation(item)
        data = dict(item["input"])
        obligation = compile_typed_obligation(
            lane=lane,
            data=data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            policy=policy,
        )
        decision = route_compiled_obligation(obligation, lane=lane, policy=policy)
        typed[intent_id] = obligation
        routing[intent_id] = decision
    return AuthoritativeRoutingPlan(typed_obligations=typed, routing_by_intent=routing)


def coerce_routing_decision(
    routing: RoutingDecision | Mapping[str, Any] | None,
    *,
    intent_id: str,
) -> RoutingDecision | None:
    """Return a typed routing decision when available."""
    if routing is None:
        return None
    if isinstance(routing, RoutingDecision):
        return routing
    try:
        return RoutingDecision.model_validate(dict(routing))
    except Exception:
        routing_id = routing.get("routing_id")
        if not routing_id:
            return None
        return RoutingDecision.model_validate(
            {
                **routing,
                "obligation_id": routing.get("obligation_id") or intent_id,
            }
        )


def ensure_authoritative_routing(
    obligations: list[dict[str, Any]],
    routing_by_intent: Mapping[str, RoutingDecision | Mapping[str, Any] | None] | None,
    *,
    policy: dict[str, Any] | None,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
) -> AuthoritativeRoutingPlan:
    """Merge caller routing with compile-then-route defaults for all obligations."""
    plan = build_authoritative_routing_plan(
        obligations,
        policy=policy,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    if not routing_by_intent:
        return plan

    merged_routing = dict(plan.routing_by_intent)
    merged_typed = dict(plan.typed_obligations)
    for obligation in obligations:
        intent_id = intent_id_for_obligation(obligation)
        provided = routing_by_intent.get(intent_id)
        coerced = coerce_routing_decision(provided, intent_id=intent_id)
        if coerced is not None:
            merged_routing[intent_id] = coerced
    return AuthoritativeRoutingPlan(
        typed_obligations=merged_typed,
        routing_by_intent=merged_routing,
    )


def require_routing_decision(
    routing: RoutingDecision | Mapping[str, Any] | None,
    *,
    intent_id: str,
    lane: str,
    policy: dict[str, Any] | None,
) -> RoutingDecision:
    """Fail closed when an enforced lane lacks a pre-computed routing decision."""
    decision = coerce_routing_decision(routing, intent_id=intent_id)
    if decision is not None:
        return decision
    if routing_enforced_for_lane(policy, lane):
        raise RuntimeError(
            f"enforced lane {lane!r} requires authoritative RoutingDecision for intent {intent_id!r}"
        )
    raise RuntimeError(f"missing routing decision for intent {intent_id!r}")
