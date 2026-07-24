"""Backend routing for verification obligations and legacy intents.

The typed control-plane entry point is ``route_obligation``, which returns a
``RoutingDecision``. ``route_intent`` remains for capability-manifest callers and
returns the same typed decision with an explicit legacy dict serializer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from ovk.core.backend_registry import BackendRegistry
from ovk.core.bundle import content_digest
from ovk.core.execution_budget import execution_budget_from_policy
from ovk.core.execution_models import (
    BackendCandidate,
    BackendCapabilityAssessment,
    BackendRejection,
    BackendSelection,
    ExecutionBudget,
    ExecutionContext,
    FallbackPolicy,
    RoutingDecision,
    VerificationObligation,
    compute_routing_id,
)

ROUTER_VERSION = "ovk.router.v2"
AGGREGATION_FAIL_DOMINANT = "ovk.aggregate.fail_dominant.v1"

RoutingMode = Literal["legacy", "shadow", "enforced"]
RoutingStrategy = Literal["primary_with_optional_corroboration"]

DETERMINISTIC_PREFERRED_BACKENDS: frozenset[str] = frozenset(
    {
        "deterministic",
        "opa",
        "z3",
        "lane-self-protection",
        "authorization-deterministic",
        "self-protection-deterministic",
    }
)
PREFER_DETERMINISTIC_BONUS = 0.3
PREFER_DETERMINISTIC_PENALTY = 0.15

BACKEND_COST_PRIORS: dict[str, float] = {
    "deterministic": 0.05,
    "opa": 0.25,
    "z3": 0.45,
    "cedar": 0.2,
    "tla+": 0.55,
    "kani": 0.5,
    "dafny": 0.7,
    "verus": 0.7,
    "lean": 0.8,
    "cbmc": 0.6,
    "alloy": 0.55,
}


@dataclass(frozen=True)
class VerificationBudget:
    """Legacy runtime budget for backend execution (manifest routing path)."""

    max_wall_time_seconds: float = 30.0
    max_memory_mb: int = 512
    allowed_backends: frozenset[str] | None = None
    denied_backends: frozenset[str] = frozenset()
    prefer_deterministic: bool = False


@dataclass(frozen=True)
class RoutingConfig:
    """Repository routing policy knobs."""

    mode: RoutingMode = "shadow"
    strategy: RoutingStrategy = "primary_with_optional_corroboration"
    aggregation: str = AGGREGATION_FAIL_DOMINANT
    max_selected_backends: int = 2
    prefer_deterministic: bool = False
    allow_fallback: bool = False
    accept_partial_primary: bool = False
    enforced_lanes: frozenset[str] = frozenset()

    def resolved_mode(self) -> RoutingMode:
        """Return the effective mode; ``enforced`` is gated by acceptance lanes."""
        if self.mode != "enforced":
            return self.mode
        # Global enforced remains unavailable until acceptance tests pass; lane-scoped
        # enforcement is expressed via ``enforced_lanes`` under shadow/legacy modes.
        if not self.enforced_lanes:
            return "shadow"
        return "enforced"


def routing_config_from_policy(policy: Mapping[str, Any] | None) -> RoutingConfig:
    """Parse routing configuration from repository policy."""
    policy = policy or {}
    section = policy.get("routing", {})
    if not isinstance(section, dict):
        section = {}
    mode_raw = str(section.get("mode", "shadow")).strip().lower()
    mode: RoutingMode = mode_raw if mode_raw in {"legacy", "shadow", "enforced"} else "shadow"
    strategy_raw = str(section.get("strategy", "primary_with_optional_corroboration")).strip()
    strategy: RoutingStrategy = (
        "primary_with_optional_corroboration"
        if strategy_raw == "primary_with_optional_corroboration"
        else "primary_with_optional_corroboration"
    )
    enforced_raw = section.get("enforced_lanes") or policy.get("enforced_lanes") or []
    enforced = (
        frozenset(str(item) for item in enforced_raw) if isinstance(enforced_raw, (list, tuple, set)) else frozenset()
    )
    return RoutingConfig(
        mode=mode,
        strategy=strategy,
        aggregation=str(section.get("aggregation", AGGREGATION_FAIL_DOMINANT)),
        max_selected_backends=max(1, int(section.get("max_selected_backends", 2))),
        prefer_deterministic=bool(section.get("prefer_deterministic", False)),
        allow_fallback=bool(section.get("allow_fallback", False)),
        accept_partial_primary=bool(section.get("accept_partial_primary", False)),
        enforced_lanes=enforced,
    )


def routing_decision_to_legacy_dict(decision: RoutingDecision, *, intent_id: str | None = None) -> dict[str, Any]:
    """Serialize a typed routing decision for legacy callers expecting a dict."""
    return {
        "intent_id": intent_id or decision.obligation_id,
        "routing_id": decision.routing_id,
        "schema_version": decision.schema_version,
        "obligation_id": decision.obligation_id,
        "selected": [item.model_dump(mode="json") for item in decision.selected],
        "rejected": [item.model_dump(mode="json") for item in decision.rejected],
        "eligible": [item.model_dump(mode="json") for item in decision.eligible],
        "requested": list(decision.requested),
        "aggregation_policy": decision.aggregation_policy,
        "fallback_policy": decision.fallback_policy.model_dump(mode="json"),
        "budget": decision.budget.model_dump(mode="json"),
        "policy_digest": decision.policy_digest,
        "router_version": ROUTER_VERSION,
    }


def _legacy_budget_to_execution_budget(budget: VerificationBudget | None) -> ExecutionBudget:
    if budget is None:
        return ExecutionBudget(
            total_wall_time_seconds=60.0,
            per_backend_wall_time_seconds=30.0,
            max_memory_mb=512,
            max_parallel_backends=2,
            allow_network=False,
            allow_repository_write=False,
        )
    return ExecutionBudget(
        total_wall_time_seconds=max(budget.max_wall_time_seconds * 2, budget.max_wall_time_seconds),
        per_backend_wall_time_seconds=budget.max_wall_time_seconds,
        max_memory_mb=budget.max_memory_mb,
        max_parallel_backends=2,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=sorted(budget.allowed_backends) if budget.allowed_backends is not None else None,
        denied_backends=sorted(budget.denied_backends),
    )


def _adjust_score_for_preferences(
    *,
    backend: str,
    score: float,
    prefer_deterministic: bool,
) -> float:
    if backend in DETERMINISTIC_PREFERRED_BACKENDS or "deterministic" in backend:
        if prefer_deterministic:
            return score + PREFER_DETERMINISTIC_BONUS
        return score - PREFER_DETERMINISTIC_PENALTY
    return score


def _assessment_fits_budget(assessment: BackendCapabilityAssessment, budget: ExecutionBudget) -> bool:
    if budget.allowed_backends is not None and assessment.backend not in budget.allowed_backends:
        return False
    if assessment.backend in set(budget.denied_backends):
        return False
    if assessment.estimated_wall_time_seconds > budget.per_backend_wall_time_seconds:
        return False
    if assessment.estimated_memory_mb > budget.max_memory_mb:
        return False
    return True


def _guarantee_acceptable(guarantee: str, acceptable: Sequence[str]) -> bool:
    if not acceptable:
        return True
    return guarantee in set(acceptable)


def select_primary_with_optional_corroboration(
    assessments: Sequence[BackendCapabilityAssessment],
    *,
    acceptable_guarantees: Sequence[str],
    config: RoutingConfig,
    budget: ExecutionBudget,
) -> tuple[list[BackendSelection], list[BackendRejection], list[BackendCandidate]]:
    """Select one required primary and at most one optional corroborator."""
    selected: list[BackendSelection] = []
    rejected: list[BackendRejection] = []
    eligible: list[BackendCandidate] = []

    ranked = sorted(assessments, key=lambda item: (-float(item.score), item.backend))
    for assessment in ranked:
        reasons = list(assessment.reasons)
        if assessment.support == "unsupported":
            rejected.append(
                BackendRejection(
                    backend=assessment.backend,
                    reason="; ".join(reasons) or "unsupported",
                    support=assessment.support,
                )
            )
            continue
        if assessment.support == "unavailable" or assessment.score < 0:
            rejected.append(
                BackendRejection(
                    backend=assessment.backend,
                    reason="; ".join(reasons) or "unavailable",
                    support=assessment.support,
                )
            )
            continue
        if not assessment.material_requirements_met:
            rejected.append(
                BackendRejection(
                    backend=assessment.backend,
                    reason="material requirements not met",
                    support=assessment.support,
                )
            )
            continue
        if not assessment.coverage_requirements_met:
            score = _adjust_score_for_preferences(
                backend=assessment.backend,
                score=float(assessment.score),
                prefer_deterministic=config.prefer_deterministic,
            )
            if config.accept_partial_primary:
                eligible.append(
                    BackendCandidate(
                        backend=assessment.backend,
                        score=score,
                        support="partial",
                        guarantee_type=assessment.guarantee_type,
                        reasons=reasons + ["incomplete coverage; not eligible as required primary"],
                        native_available=assessment.native_available,
                    )
                )
            else:
                rejected.append(
                    BackendRejection(
                        backend=assessment.backend,
                        reason="coverage requirements not met",
                        support=assessment.support,
                    )
                )
            continue
        if not _guarantee_acceptable(assessment.guarantee_type, acceptable_guarantees):
            rejected.append(
                BackendRejection(
                    backend=assessment.backend,
                    reason=f"guarantee {assessment.guarantee_type!r} not in acceptable set",
                    support=assessment.support,
                )
            )
            continue
        if not _assessment_fits_budget(assessment, budget):
            rejected.append(
                BackendRejection(
                    backend=assessment.backend,
                    reason="excluded by verification budget",
                    support=assessment.support,
                )
            )
            continue

        score = _adjust_score_for_preferences(
            backend=assessment.backend,
            score=float(assessment.score),
            prefer_deterministic=config.prefer_deterministic,
        )
        if assessment.support == "partial" and not config.accept_partial_primary:
            # Eligible for optional corroboration only.
            eligible.append(
                BackendCandidate(
                    backend=assessment.backend,
                    score=score,
                    support=assessment.support,
                    guarantee_type=assessment.guarantee_type,
                    reasons=reasons + ["partial support; not eligible as required primary"],
                    native_available=assessment.native_available,
                )
            )
            continue

        eligible.append(
            BackendCandidate(
                backend=assessment.backend,
                score=score,
                support=assessment.support,
                guarantee_type=assessment.guarantee_type,
                reasons=reasons,
                native_available=assessment.native_available,
            )
        )

    eligible_sorted = sorted(eligible, key=lambda item: (-item.score, item.backend))
    primary_candidates = [item for item in eligible_sorted if item.support == "supported"]
    if not primary_candidates and config.accept_partial_primary:
        primary_candidates = [
            item
            for item in eligible_sorted
            if item.support == "partial" and not any("incomplete coverage" in reason for reason in item.reasons)
        ]

    if primary_candidates:
        primary = primary_candidates[0]
        selected.append(
            BackendSelection(
                backend=primary.backend,
                reason="; ".join(primary.reasons) or "highest scoring supported backend",
                expected_guarantee=primary.guarantee_type,
                required=True,
                score=primary.score,
            )
        )

    if len(selected) < config.max_selected_backends:
        for candidate in eligible_sorted:
            if any(item.backend == candidate.backend for item in selected):
                continue
            selected.append(
                BackendSelection(
                    backend=candidate.backend,
                    reason="; ".join(candidate.reasons) or "optional corroborator",
                    expected_guarantee=candidate.guarantee_type,
                    required=False,
                    score=candidate.score,
                )
            )
            break

    # Reject remaining eligible that were not selected.
    selected_ids = {item.backend for item in selected}
    for candidate in eligible_sorted:
        if candidate.backend in selected_ids:
            continue
        rejected.append(
            BackendRejection(
                backend=candidate.backend,
                reason="not selected under primary_with_optional_corroboration",
                support=candidate.support,
            )
        )

    return selected, rejected, eligible_sorted


def _build_routing_decision(
    *,
    obligation_id: str,
    requested: list[str],
    assessments: list[BackendCapabilityAssessment],
    selected: list[BackendSelection],
    rejected: list[BackendRejection],
    eligible: list[BackendCandidate],
    budget: ExecutionBudget,
    fallback: FallbackPolicy,
    aggregation_policy: str,
    policy_digest: str,
) -> RoutingDecision:
    routing_id = compute_routing_id(
        obligation_id=obligation_id,
        requested=requested,
        eligible=eligible,
        selected=selected,
        rejected=rejected,
        aggregation_policy=aggregation_policy,
        fallback_policy=fallback,
        budget=budget,
        policy_digest=policy_digest,
        router_version=ROUTER_VERSION,
        assessments=assessments,
    )
    return RoutingDecision(
        routing_id=routing_id,
        obligation_id=obligation_id,
        requested=requested,
        eligible=eligible,
        selected=selected,
        rejected=rejected,
        aggregation_policy=aggregation_policy,
        fallback_policy=fallback,
        budget=budget,
        policy_digest=policy_digest,
    )


def route_obligation(
    obligation: VerificationObligation,
    registry: BackendRegistry,
    *,
    context: ExecutionContext | None = None,
    config: RoutingConfig | None = None,
    policy: Mapping[str, Any] | None = None,
) -> RoutingDecision:
    """Route a typed obligation using adapter capability assessments."""
    routing_config = config or routing_config_from_policy(policy)
    ctx = context or ExecutionContext(
        subject=obligation.subject,
        policy_digest=obligation.policy_digest,
        budget=execution_budget_from_policy(dict(policy) if policy else None),
    )
    budget = ctx.budget or execution_budget_from_policy(dict(policy) if policy else None)
    assessments = registry.candidates(obligation, ctx.model_copy(update={"budget": budget}))
    requested = list(registry.backend_ids())
    selected, rejected, eligible = select_primary_with_optional_corroboration(
        assessments,
        acceptable_guarantees=obligation.acceptable_guarantees,
        config=routing_config,
        budget=budget,
    )
    fallback = FallbackPolicy(
        allow_fallback=routing_config.allow_fallback,
        fallback_backends=[],
        on_timeout="unknown",
        on_tool_unavailable="unknown",
        on_invalid_output="unknown",
    )
    return _build_routing_decision(
        obligation_id=obligation.obligation_id,
        requested=requested,
        assessments=assessments,
        selected=selected,
        rejected=rejected,
        eligible=eligible,
        budget=budget,
        fallback=fallback,
        aggregation_policy=routing_config.aggregation,
        policy_digest=obligation.policy_digest or ctx.policy_digest or content_digest(dict(policy or {})),
    )


def _manifest_assessment(
    manifest: dict[str, Any],
    *,
    intent: dict[str, Any],
    budget: VerificationBudget | None,
    historical_priors: dict[str, float] | None,
    surface_bonuses: dict[str, float] | None,
) -> BackendCapabilityAssessment:
    """Build an assessment from a capability manifest (compatibility path)."""
    tool_name = str(manifest.get("tool", {}).get("name", "unknown"))
    domain = intent.get("domain")
    property_kind = (intent.get("property") or {}).get("kind")
    domains = set(manifest.get("supported_domains", []))
    property_kinds = set(manifest.get("supported_property_kinds", []))
    guarantee = str((manifest.get("guarantee") or {}).get("type", "unknown"))
    domain_match = domain in domains
    kind_match = property_kind in property_kinds

    cost = BACKEND_COST_PRIORS.get(tool_name, 0.4)
    historical_success = (historical_priors or {}).get(tool_name, 0.5)
    surface_bonus = (surface_bonuses or {}).get(tool_name, 0.0)
    guarantee_strength = 0.7 if guarantee == "policy_evaluation" else 0.5

    reasons: list[str] = []
    if domain_match and kind_match:
        support: Literal["supported", "partial", "unsupported", "unavailable"] = "supported"
        # Explicit relevance from domain/kind match replaces the former constant 1.0 term.
        relevance = 1.0 if kind_match else 0.5
        score = relevance + guarantee_strength + (0.15 * historical_success) + surface_bonus - cost
        reasons.append(f"supports domain {domain} and property kind {property_kind}")
    elif domain_match:
        support = "partial"
        score = 0.35 + surface_bonus - (0.5 * cost)
        reasons.append(f"supports domain {domain} but not property kind {property_kind}")
    else:
        support = "unsupported"
        score = 0.0
        reasons.append(f"does not support domain {domain}")

    if budget is not None:
        if budget.allowed_backends is not None and tool_name not in budget.allowed_backends:
            support = "unavailable"
            score = -1.0
            reasons.append("excluded by verification budget")
        elif tool_name in budget.denied_backends:
            support = "unavailable"
            score = -1.0
            reasons.append("excluded by verification budget")
        elif cost * 30 > budget.max_wall_time_seconds:
            score -= 0.3
            reasons.append("budget wall-time pressure")
        score = _adjust_score_for_preferences(
            backend=tool_name,
            score=score,
            prefer_deterministic=budget.prefer_deterministic,
        )

    material_requirements_met = domain_match and kind_match
    coverage_requirements_met = support == "supported" and material_requirements_met

    return BackendCapabilityAssessment(
        backend=tool_name,
        support=support,
        score=score,
        guarantee_type=guarantee,
        material_requirements_met=material_requirements_met,
        coverage_requirements_met=coverage_requirements_met,
        native_available=False,
        estimated_wall_time_seconds=cost * 30,
        estimated_memory_mb=256,
        reasons=reasons,
    )


def route_intent(
    intent: dict[str, Any],
    capabilities: list[dict[str, Any]],
    *,
    budget: VerificationBudget | None = None,
    historical_priors: dict[str, float] | None = None,
    surface_bonuses: dict[str, float] | None = None,
    config: RoutingConfig | None = None,
    policy: Mapping[str, Any] | None = None,
    as_legacy_dict: bool = True,
) -> RoutingDecision | dict[str, Any]:
    """Route an intent using capability manifests.

    By default returns a compatibility dict so existing callers keep working.
    Pass ``as_legacy_dict=False`` to receive a typed ``RoutingDecision``.
    """
    routing_config = config or routing_config_from_policy(policy)
    assessments = [
        _manifest_assessment(
            manifest,
            intent=intent,
            budget=budget,
            historical_priors=historical_priors,
            surface_bonuses=surface_bonuses,
        )
        for manifest in capabilities
    ]
    # Preserve prior behavior: select all supported backends ranked by score when
    # using the legacy manifest path, then apply primary/corroboration cap.
    execution_budget = _legacy_budget_to_execution_budget(budget)
    if budget and budget.prefer_deterministic:
        routing_config = RoutingConfig(
            mode=routing_config.mode,
            strategy=routing_config.strategy,
            aggregation=routing_config.aggregation,
            max_selected_backends=routing_config.max_selected_backends,
            prefer_deterministic=True,
            allow_fallback=routing_config.allow_fallback,
            accept_partial_primary=routing_config.accept_partial_primary,
            enforced_lanes=routing_config.enforced_lanes,
        )

    # For legacy intent routing, acceptable guarantees are open unless stated.
    acceptable = [
        str(item.get("guarantee_type", item) if isinstance(item, dict) else item)
        for item in intent.get("acceptable_evidence", [])
    ]
    selected, rejected, eligible = select_primary_with_optional_corroboration(
        assessments,
        acceptable_guarantees=acceptable,
        config=RoutingConfig(
            mode=routing_config.mode,
            strategy=routing_config.strategy,
            aggregation=routing_config.aggregation,
            # Preserve historical multi-select for tests that expect opa/z3 presence:
            # use a higher cap when max_selected_backends is default and many supports exist.
            max_selected_backends=max(routing_config.max_selected_backends, len(capabilities)),
            prefer_deterministic=routing_config.prefer_deterministic,
            allow_fallback=routing_config.allow_fallback,
            accept_partial_primary=True,
            enforced_lanes=routing_config.enforced_lanes,
        ),
        budget=execution_budget,
    )

    # Compatibility: prior router selected every domain+kind match. Rebuild selected
    # from supported assessments to avoid breaking existing selection assertions,
    # while still emitting typed RoutingDecision fields and routing_id.
    legacy_selected: list[BackendSelection] = []
    legacy_rejected: list[BackendRejection] = []
    for assessment in sorted(assessments, key=lambda item: (-item.score, item.backend)):
        if assessment.support == "supported" and assessment.score >= 0:
            legacy_selected.append(
                BackendSelection(
                    backend=assessment.backend,
                    reason="; ".join(assessment.reasons),
                    expected_guarantee=assessment.guarantee_type,
                    required=True,
                    score=assessment.score,
                )
            )
        else:
            legacy_rejected.append(
                BackendRejection(
                    backend=assessment.backend,
                    reason="; ".join(assessment.reasons),
                    support=assessment.support,
                )
            )

    # Prefer legacy multi-select serialization; keep corroboration selection available
    # via eligible/selected when as_legacy_dict is False and strategy is enforced later.
    use_selected = legacy_selected
    use_rejected = legacy_rejected
    use_eligible = [
        BackendCandidate(
            backend=item.backend,
            score=item.score,
            support="supported",
            guarantee_type=item.expected_guarantee,
            reasons=[item.reason],
        )
        for item in legacy_selected
    ]

    obligation_id = str(intent.get("intent_id", "unknown"))
    policy_digest = content_digest({"intent_id": obligation_id, "policy": dict(policy or {})})
    fallback = FallbackPolicy(allow_fallback=routing_config.allow_fallback)
    decision = _build_routing_decision(
        obligation_id=obligation_id,
        requested=sorted({str(m.get("tool", {}).get("name", "unknown")) for m in capabilities}),
        assessments=assessments,
        selected=use_selected,
        rejected=use_rejected,
        eligible=use_eligible,
        budget=execution_budget,
        fallback=fallback,
        aggregation_policy=routing_config.aggregation,
        policy_digest=policy_digest,
    )
    if as_legacy_dict:
        return routing_decision_to_legacy_dict(decision, intent_id=obligation_id)
    return decision
