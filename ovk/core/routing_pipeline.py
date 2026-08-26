"""Authoritative compile-then-route pipeline for production obligations.

Intent identity classifies a proposition; it is not an execution identity. A
single intent may legitimately produce several obligation instances from one PR.
Every instance is compiled and routed exactly once and receives its own stable
instance key. Legacy intent-keyed routing is accepted only when an intent has a
single unambiguous instance.
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
from ovk.core.bundle import content_digest
from ovk.core.ci_secrets_compiler import compile_ci_secrets_obligation
from ovk.core.coverage_contract import CoverageContractRegistry
from ovk.core.coverage_policy_binding import coverage_policy_from_obligation
from ovk.core.deployment_compiler import compile_deployment_obligation
from ovk.core.execution_budget import execution_budget_from_policy
from ovk.core.execution_models import ExecutionContext, RoutingDecision, VerificationObligation, compute_routing_id
from ovk.core.infrastructure_compiler import compile_infrastructure_obligation
from ovk.core.policy_config import routing_enforced_for_lane
from ovk.core.router import (
    ROUTER_VERSION,
    RoutingConfig,
    route_obligation,
    routing_config_from_policy,
    routing_decision_to_legacy_dict,
)
from ovk.core.self_protection_compiler import compile_self_protection_obligation, resolve_metadata_trusted

LANE_TO_INTENT = {
    "self_protection": "agent-cannot-disable-own-ci-gate",
    "authorization": "no-admin-route-bypass",
    "infrastructure": "no-public-sensitive-resource",
    "ci_secrets": "no-secrets-in-untrusted-context",
    "deployment": "no-skipped-approval-state",
}


def intent_id_for_obligation(obligation: dict[str, Any]) -> str:
    lane = str(obligation["lane"])
    return str(obligation.get("intent_id") or LANE_TO_INTENT.get(lane, lane))


def obligation_instance_key(obligation: Mapping[str, Any]) -> str:
    """Return a stable identity for one raw obligation instance.

    The key binds semantic intent, lane, input, material format and compiler job
    identity. It deliberately does not replace the typed ``obligation_id``; it
    identifies the caller-visible instance that produced that typed obligation.
    """
    lane = str(obligation["lane"])
    payload = {
        "lane": lane,
        "intent_id": str(obligation.get("intent_id") or LANE_TO_INTENT.get(lane, lane)),
        "job_id": obligation.get("job_id"),
        "input_format": str(obligation.get("input_format", "infra")),
        "input": obligation.get("input"),
    }
    return "obi-" + content_digest(payload)[:32]


RegistryBuilder = Callable[[], BackendRegistry]
CompilerFn = Callable[..., VerificationObligation]

_LANE_REGISTRY: dict[str, RegistryBuilder] = {
    "authorization": build_authorization_registry,
    "self_protection": build_self_protection_registry,
    "infrastructure": build_infrastructure_registry,
    "ci_secrets": build_ci_secrets_registry,
    "deployment": build_deployment_registry,
}


def _compile_authorization(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None, policy: dict[str, Any] | None) -> VerificationObligation:
    return compile_authorization_obligation(data, repo=repo, head_sha=head_sha, base_sha=base_sha, policy=policy)


def _compile_self_protection(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None, policy: dict[str, Any] | None) -> VerificationObligation:
    return compile_self_protection_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        metadata_trusted=resolve_metadata_trusted(
            policy, data=data, repo=repo, head_sha=head_sha, base_sha=base_sha
        ),
    )


def _compile_infrastructure(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None, policy: dict[str, Any] | None) -> VerificationObligation:
    return compile_infrastructure_obligation(data, repo=repo, head_sha=head_sha, base_sha=base_sha, policy=policy)


def _compile_ci_secrets(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None, policy: dict[str, Any] | None) -> VerificationObligation:
    return compile_ci_secrets_obligation(data, repo=repo, head_sha=head_sha, base_sha=base_sha, policy=policy)


def _compile_deployment(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None, policy: dict[str, Any] | None) -> VerificationObligation:
    return compile_deployment_obligation(data, repo=repo, head_sha=head_sha, base_sha=base_sha, policy=policy)


_LANE_COMPILERS: dict[str, CompilerFn] = {
    "authorization": _compile_authorization,
    "self_protection": _compile_self_protection,
    "infrastructure": _compile_infrastructure,
    "ci_secrets": _compile_ci_secrets,
    "deployment": _compile_deployment,
}


@dataclass(frozen=True)
class AuthoritativeRoutingPlan:
    """Typed obligations and routes keyed by unambiguous obligation instance."""

    typed_obligations: dict[str, VerificationObligation]
    routing_by_instance: dict[str, RoutingDecision]
    intent_by_instance: dict[str, str]

    def instance_key(self, raw_obligation: Mapping[str, Any]) -> str:
        return obligation_instance_key(raw_obligation)

    def typed_for(self, raw_obligation: Mapping[str, Any]) -> VerificationObligation | None:
        return self.typed_obligations.get(self.instance_key(raw_obligation))

    def routing_for(self, raw_obligation: Mapping[str, Any]) -> RoutingDecision | None:
        return self.routing_by_instance.get(self.instance_key(raw_obligation))

    def instances_for_intent(self, intent_id: str) -> tuple[str, ...]:
        return tuple(sorted(key for key, value in self.intent_by_instance.items() if value == intent_id))

    @property
    def routing_by_intent(self) -> dict[str, RoutingDecision]:
        """Compatibility view containing only unambiguous single-instance intents."""
        result: dict[str, RoutingDecision] = {}
        intents = sorted(set(self.intent_by_instance.values()))
        for intent_id in intents:
            keys = self.instances_for_intent(intent_id)
            if len(keys) == 1:
                result[intent_id] = self.routing_by_instance[keys[0]]
        return result

    def routing_metadata_list(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for instance_id, decision in sorted(self.routing_by_instance.items()):
            payload = routing_decision_to_legacy_dict(
                decision, intent_id=self.intent_by_instance[instance_id]
            )
            payload["obligation_instance_id"] = instance_id
            rows.append(payload)
        return rows

    def legacy_routing_by_intent(self) -> dict[str, dict[str, Any]]:
        """Return legacy routing only when every intent is unambiguous."""
        ambiguous = [
            intent_id
            for intent_id in sorted(set(self.intent_by_instance.values()))
            if len(self.instances_for_intent(intent_id)) != 1
        ]
        if ambiguous:
            raise RuntimeError(
                "intent-keyed routing is ambiguous for multi-instance intents: "
                + ", ".join(ambiguous)
            )
        return {
            intent_id: routing_decision_to_legacy_dict(decision, intent_id=intent_id)
            for intent_id, decision in self.routing_by_intent.items()
        }


def compile_typed_obligation(*, lane: str, data: dict[str, Any], repo: str, head_sha: str, base_sha: str | None = None, policy: dict[str, Any] | None = None) -> VerificationObligation:
    compiler = _LANE_COMPILERS.get(lane)
    if compiler is None:
        raise ValueError(f"no typed compiler registered for lane {lane!r}")
    return compiler(data, repo=repo, head_sha=head_sha, base_sha=base_sha, policy=policy)


def _externally_recomputable_routing_id(decision: RoutingDecision) -> str:
    return compute_routing_id(
        obligation_id=decision.obligation_id,
        requested=list(decision.requested),
        eligible=list(decision.eligible),
        selected=list(decision.selected),
        rejected=list(decision.rejected),
        aggregation_policy=decision.aggregation_policy,
        fallback_policy=decision.fallback_policy,
        budget=decision.budget,
        policy_digest=decision.policy_digest,
        router_version=ROUTER_VERSION,
        assessments=None,
    )


def route_compiled_obligation(obligation: VerificationObligation, *, lane: str, policy: dict[str, Any] | None = None) -> RoutingDecision:
    registry_builder = _LANE_REGISTRY.get(lane)
    if registry_builder is None:
        raise ValueError(f"no registry registered for lane {lane!r}")
    raw_registry = registry_builder()
    routing_config = routing_config_from_policy(policy)
    budget = execution_budget_from_policy(policy)
    enforced = routing_enforced_for_lane(policy, lane)
    registry = CoverageContractRegistry(
        raw_registry,
        enforced=enforced,
        coverage_policy=coverage_policy_from_obligation(obligation),
    )
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
    routed = route_obligation(
        obligation,
        registry,  # type: ignore[arg-type]
        context=context,
        config=config,
        policy=policy,
    )
    return routed.model_copy(update={"routing_id": _externally_recomputable_routing_id(routed)})


def build_authoritative_routing_plan(
    obligations: list[dict[str, Any]], *, policy: dict[str, Any] | None = None,
    repo: str, head_sha: str, base_sha: str | None = None,
) -> AuthoritativeRoutingPlan:
    typed: dict[str, VerificationObligation] = {}
    routing: dict[str, RoutingDecision] = {}
    intents: dict[str, str] = {}
    for item in obligations:
        lane = str(item["lane"])
        if lane not in _LANE_COMPILERS or lane not in _LANE_REGISTRY:
            continue
        instance_id = obligation_instance_key(item)
        if instance_id in typed:
            raise RuntimeError(f"duplicate obligation instance in routing plan: {instance_id}")
        obligation = compile_typed_obligation(
            lane=lane,
            data=dict(item["input"]),
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            policy=policy,
        )
        decision = route_compiled_obligation(obligation, lane=lane, policy=policy)
        typed[instance_id] = obligation
        routing[instance_id] = decision
        intents[instance_id] = intent_id_for_obligation(item)
    return AuthoritativeRoutingPlan(
        typed_obligations=typed,
        routing_by_instance=routing,
        intent_by_instance=intents,
    )


def coerce_routing_decision(routing: RoutingDecision | Mapping[str, Any] | None, *, intent_id: str) -> RoutingDecision | None:
    if routing is None:
        return None
    if isinstance(routing, RoutingDecision):
        return routing
    payload = dict(routing)
    try:
        return RoutingDecision.model_validate(payload)
    except Exception:
        if not payload.get("routing_id"):
            return None
        payload.setdefault("obligation_id", intent_id)
        try:
            return RoutingDecision.model_validate(payload)
        except Exception:
            return None


def _assert_matches_canonical(provided: RoutingDecision, canonical: RoutingDecision, *, intent_id: str) -> None:
    if provided.obligation_id != canonical.obligation_id:
        raise RuntimeError(
            f"caller routing obligation mismatch for {intent_id!r}: "
            f"{provided.obligation_id} != {canonical.obligation_id}"
        )
    if provided.policy_digest != canonical.policy_digest:
        raise RuntimeError(f"caller routing policy mismatch for {intent_id!r}")
    if provided.routing_id != canonical.routing_id:
        raise RuntimeError(f"caller routing is stale or non-canonical for {intent_id!r}")
    if provided.model_dump(mode="json") != canonical.model_dump(mode="json"):
        raise RuntimeError(f"caller routing payload does not match canonical route for {intent_id!r}")


def ensure_authoritative_routing(
    obligations: list[dict[str, Any]],
    routing_by_intent: Mapping[str, RoutingDecision | Mapping[str, Any] | None] | None,
    *, policy: dict[str, Any] | None, repo: str, head_sha: str, base_sha: str | None = None,
) -> AuthoritativeRoutingPlan:
    plan = build_authoritative_routing_plan(
        obligations, policy=policy, repo=repo, head_sha=head_sha, base_sha=base_sha
    )
    if not routing_by_intent:
        return plan
    for intent_id, provided_raw in routing_by_intent.items():
        if provided_raw is None:
            continue
        instance_ids = plan.instances_for_intent(str(intent_id))
        if not instance_ids:
            continue
        if len(instance_ids) != 1:
            raise RuntimeError(
                f"caller intent-keyed routing is ambiguous for {intent_id!r}; "
                "provide no compatibility route and use authoritative per-obligation routing"
            )
        provided = coerce_routing_decision(provided_raw, intent_id=str(intent_id))
        if provided is None:
            raise RuntimeError(f"invalid caller routing decision for {intent_id!r}")
        canonical = plan.routing_by_instance[instance_ids[0]]
        _assert_matches_canonical(provided, canonical, intent_id=str(intent_id))
    return plan


def require_routing_decision(
    routing: RoutingDecision | Mapping[str, Any] | None, *, intent_id: str,
    lane: str, policy: dict[str, Any] | None,
) -> RoutingDecision:
    decision = coerce_routing_decision(routing, intent_id=intent_id)
    if decision is not None:
        return decision
    if routing_enforced_for_lane(policy, lane):
        raise RuntimeError(
            f"enforced lane {lane!r} requires authoritative RoutingDecision for intent {intent_id!r}"
        )
    raise RuntimeError(f"missing routing decision for intent {intent_id!r}")
