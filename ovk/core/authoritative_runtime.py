"""Execution entry point for an already-routed authoritative verification plan.

The kernel owns compilation and routing. Execution must consume that exact plan;
it must never silently rebuild routing from mutable environment state. This
module provides the production execution surface and validates the plan seal
before any backend adapter is compiled or run.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ovk.core.adapter_runtime import _evaluate_obligation
from ovk.core.execution_models import RoutingDecision, VerificationObligation
from ovk.core.routing_pipeline import (
    AuthoritativeRoutingPlan,
    LANE_TO_INTENT,
    intent_id_for_obligation,
)


class AuthoritativePlanError(RuntimeError):
    """Raised when a supplied authoritative routing plan is internally invalid."""


def _expected_subject(
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> dict[str, str]:
    payload = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        payload["base_sha"] = base_sha
    return payload


def _validate_subject(
    obligation: VerificationObligation,
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    intent_id: str,
) -> None:
    subject = obligation.subject
    if subject.repo != repo or subject.head_sha != head_sha:
        raise AuthoritativePlanError(
            f"authoritative obligation subject mismatch for {intent_id!r}: "
            f"expected {repo}@{head_sha}, got {subject.repo}@{subject.head_sha}"
        )
    if base_sha is not None and subject.base_sha != base_sha:
        raise AuthoritativePlanError(
            f"authoritative obligation base_sha mismatch for {intent_id!r}: "
            f"expected {base_sha}, got {subject.base_sha}"
        )


def _validate_route(
    routing: RoutingDecision,
    obligation: VerificationObligation,
    *,
    intent_id: str,
) -> None:
    if routing.obligation_id != obligation.obligation_id:
        raise AuthoritativePlanError(
            f"routing obligation_id mismatch for {intent_id!r}: "
            f"{routing.obligation_id} != {obligation.obligation_id}"
        )
    if routing.policy_digest != obligation.policy_digest:
        raise AuthoritativePlanError(
            f"routing policy_digest mismatch for {intent_id!r}"
        )
    if not routing.routing_id:
        raise AuthoritativePlanError(f"missing routing_id for {intent_id!r}")

    requested = set(routing.requested)
    eligible = {item.backend: item for item in routing.eligible}
    rejected = {item.backend for item in routing.rejected}
    selected_ids = [item.backend for item in routing.selected]
    if len(selected_ids) != len(set(selected_ids)):
        raise AuthoritativePlanError(f"duplicate selected backend for {intent_id!r}")

    for selected in routing.selected:
        if selected.backend not in requested:
            raise AuthoritativePlanError(
                f"selected backend {selected.backend!r} was not requested for {intent_id!r}"
            )
        candidate = eligible.get(selected.backend)
        if candidate is None:
            raise AuthoritativePlanError(
                f"selected backend {selected.backend!r} was not eligible for {intent_id!r}"
            )
        if selected.backend in rejected:
            raise AuthoritativePlanError(
                f"selected backend {selected.backend!r} is also rejected for {intent_id!r}"
            )
        if selected.expected_guarantee != candidate.guarantee_type:
            raise AuthoritativePlanError(
                f"selected guarantee mismatch for {intent_id!r}/{selected.backend!r}: "
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
    """Validate that *plan* is the exact typed plan for the supplied obligations.

    Experimental/catalog lanes without a typed production compiler are ignored,
    matching ``build_authoritative_routing_plan``. For all five production lanes,
    missing, stale or structurally forged routing fails closed.
    """
    expected_intents: set[str] = set()
    for item in obligations:
        lane = str(item.get("lane", ""))
        if lane not in LANE_TO_INTENT:
            continue
        intent_id = intent_id_for_obligation(item)
        expected_intents.add(intent_id)
        typed = plan.typed_obligations.get(intent_id)
        routing = plan.routing_by_intent.get(intent_id)
        if typed is None:
            raise AuthoritativePlanError(
                f"missing typed obligation for production intent {intent_id!r}"
            )
        if routing is None:
            raise AuthoritativePlanError(
                f"missing routing decision for production intent {intent_id!r}"
            )
        if typed.intent_id != intent_id:
            raise AuthoritativePlanError(
                f"typed obligation intent mismatch: key={intent_id!r}, value={typed.intent_id!r}"
            )
        _validate_subject(
            typed,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            intent_id=intent_id,
        )
        _validate_route(routing, typed, intent_id=intent_id)

    extra_typed = set(plan.typed_obligations) - expected_intents
    extra_routes = set(plan.routing_by_intent) - expected_intents
    if extra_typed or extra_routes:
        raise AuthoritativePlanError(
            "authoritative plan contains obligations not present in this execution: "
            f"typed={sorted(extra_typed)}, routing={sorted(extra_routes)}"
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
            futures = [
                pool.submit(_evaluate_obligation, obligation, **kwargs)
                for obligation in obligations
            ]
            return [future.result() for future in futures]

    return [_evaluate_obligation(obligation, **kwargs) for obligation in obligations]
