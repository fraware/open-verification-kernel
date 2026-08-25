"""Execution entry point for an already-routed authoritative verification plan.

The kernel owns compilation and routing. Execution consumes that exact plan and
validates every caller-visible obligation instance before any backend runs.
Semantic intent classifies a proposition; it is never used as execution identity.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ovk.core.adapter_runtime import _evaluate_obligation
from ovk.core.execution_models import RoutingDecision, VerificationObligation
from ovk.core.fallback_rules import strict_fallback_rules_from_policy
from ovk.core.routing_pipeline import AuthoritativeRoutingPlan, LANE_TO_INTENT, intent_id_for_obligation


class AuthoritativePlanError(RuntimeError):
    """Raised when a supplied authoritative routing plan is internally invalid."""


def _validate_subject(
    obligation: VerificationObligation,
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    identity: str,
) -> None:
    subject = obligation.subject
    if subject.repo != repo or subject.head_sha != head_sha:
        raise AuthoritativePlanError(
            f"authoritative obligation subject mismatch for {identity}: "
            f"expected {repo}@{head_sha}, got {subject.repo}@{subject.head_sha}"
        )
    if base_sha is not None and subject.base_sha != base_sha:
        raise AuthoritativePlanError(
            f"authoritative obligation base_sha mismatch for {identity}: "
            f"expected {base_sha}, got {subject.base_sha}"
        )


def _validate_route(
    routing: RoutingDecision,
    obligation: VerificationObligation,
    *,
    identity: str,
) -> None:
    if routing.obligation_id != obligation.obligation_id:
        raise AuthoritativePlanError(
            f"routing obligation_id mismatch for {identity}: "
            f"{routing.obligation_id} != {obligation.obligation_id}"
        )
    if routing.policy_digest != obligation.policy_digest:
        raise AuthoritativePlanError(f"routing policy_digest mismatch for {identity}")
    if not routing.routing_id:
        raise AuthoritativePlanError(f"missing routing_id for {identity}")

    requested = set(routing.requested)
    eligible = {item.backend: item for item in routing.eligible}
    rejected = {item.backend for item in routing.rejected}
    selected_ids = [item.backend for item in routing.selected]
    if len(selected_ids) != len(set(selected_ids)):
        raise AuthoritativePlanError(f"duplicate selected backend for {identity}")

    for selected in routing.selected:
        if selected.backend not in requested:
            raise AuthoritativePlanError(
                f"selected backend {selected.backend!r} was not requested for {identity}"
            )
        candidate = eligible.get(selected.backend)
        if candidate is None:
            raise AuthoritativePlanError(
                f"selected backend {selected.backend!r} was not eligible for {identity}"
            )
        if selected.backend in rejected:
            raise AuthoritativePlanError(
                f"selected backend {selected.backend!r} is also rejected for {identity}"
            )
        if selected.expected_guarantee != candidate.guarantee_type:
            raise AuthoritativePlanError(
                f"selected guarantee mismatch for {identity}/{selected.backend!r}: "
                f"{selected.expected_guarantee!r} != {candidate.guarantee_type!r}"
            )


def validate_authoritative_plan(
    obligations: list[dict[str, Any]],
    plan: AuthoritativeRoutingPlan,
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
) -> None:
    """Validate the exact per-instance typed plan for production obligations."""
    expected_instances: set[str] = set()
    for item in obligations:
        lane = str(item.get("lane", ""))
        if lane not in LANE_TO_INTENT:
            continue

        intent_id = intent_id_for_obligation(item)
        instance_id = plan.instance_key(item)
        identity = f"intent={intent_id!r}, instance={instance_id!r}"
        if instance_id in expected_instances:
            raise AuthoritativePlanError(f"duplicate obligation instance in execution: {identity}")
        expected_instances.add(instance_id)

        typed = plan.typed_obligations.get(instance_id)
        routing = plan.routing_by_instance.get(instance_id)
        recorded_intent = plan.intent_by_instance.get(instance_id)
        if typed is None:
            raise AuthoritativePlanError(f"missing typed obligation for {identity}")
        if routing is None:
            raise AuthoritativePlanError(f"missing routing decision for {identity}")
        if recorded_intent != intent_id:
            raise AuthoritativePlanError(
                f"authoritative plan intent mismatch for instance {instance_id!r}: "
                f"{recorded_intent!r} != {intent_id!r}"
            )
        if typed.intent_id != intent_id:
            raise AuthoritativePlanError(
                f"typed obligation intent mismatch for instance {instance_id!r}: "
                f"{typed.intent_id!r} != {intent_id!r}"
            )
        _validate_subject(
            typed,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            identity=identity,
        )
        _validate_route(routing, typed, identity=identity)

    extra_typed = set(plan.typed_obligations) - expected_instances
    extra_routes = set(plan.routing_by_instance) - expected_instances
    extra_intents = set(plan.intent_by_instance) - expected_instances
    if extra_typed or extra_routes or extra_intents:
        raise AuthoritativePlanError(
            "authoritative plan contains instances not present in this execution: "
            f"typed={sorted(extra_typed)}, routing={sorted(extra_routes)}, "
            f"intent_bindings={sorted(extra_intents)}"
        )


def _validate_authoritative_fallback(
    plan: AuthoritativeRoutingPlan,
    *,
    policy: dict[str, Any] | None,
) -> None:
    """Fail closed until exact cross-backend fallback is fully evidence-bound."""
    try:
        rules = strict_fallback_rules_from_policy(policy)
    except ValueError as exc:
        raise AuthoritativePlanError(str(exc)) from exc

    # Validate every instance. The intent compatibility view intentionally omits
    # ambiguous multi-instance intents and therefore cannot be used for safety
    # checks here.
    if any(route.fallback_policy.allow_fallback for route in plan.routing_by_instance.values()):
        raise AuthoritativePlanError(
            "legacy broad allow_fallback is forbidden in authoritative execution; "
            "fallback requires an exact evidence-bound rule"
        )
    if rules:
        raise AuthoritativePlanError(
            "explicit fallback_rules are valid but cross-backend fallback execution "
            "is not yet evidence-bound; authoritative execution fails closed"
        )


def execute_authoritative_plan(
    obligations: list[dict[str, Any]],
    plan: AuthoritativeRoutingPlan,
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    parallel: bool = True,
    policy: dict[str, Any] | None = None,
    evidence_schema_version: str = "ovk.evidence.v3",
):
    """Execute the exact routing plan produced by the kernel, without rerouting."""
    if not obligations:
        return []
    validate_authoritative_plan(
        obligations,
        plan,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    _validate_authoritative_fallback(plan, policy=policy)

    kwargs = {
        "routing_plan": plan,
        "repo": repo,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "cache_dir": cache_dir,
        "use_cache": use_cache,
        "policy": policy,
        "evidence_schema_version": evidence_schema_version,
    }
    if parallel and len(obligations) > 1:
        with ThreadPoolExecutor(max_workers=min(len(obligations), 5)) as pool:
            futures = [pool.submit(_evaluate_obligation, obligation, **kwargs) for obligation in obligations]
            return [future.result() for future in futures]

    return [_evaluate_obligation(obligation, **kwargs) for obligation in obligations]
