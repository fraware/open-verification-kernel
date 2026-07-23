"""Execute compiled obligations through lane adapters with routing metadata.

Shadow mode runs the typed control plane beside legacy ``evaluate_lane``;
legacy evidence remains authoritative.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ovk.adapters.authorization import build_authorization_registry
from ovk.adapters.ci_secrets import build_ci_secrets_registry
from ovk.adapters.deployment import build_deployment_registry
from ovk.adapters.infrastructure import build_infrastructure_registry
from ovk.adapters.lane import build_default_lane_registry
from ovk.adapters.self_protection import build_self_protection_registry
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_control_plane import BackendControlPlane, compare_shadow_to_legacy
from ovk.core.bundle import content_digest
from ovk.core.ci_secrets_compiler import compile_ci_secrets_obligation
from ovk.core.deployment_compiler import compile_deployment_obligation
from ovk.core.evidence_from_execution import execution_record_to_evidence
from ovk.core.execution_budget import LocalSubprocessWorker, execution_budget_from_policy
from ovk.core.execution_models import ExecutionContext
from ovk.core.infrastructure_compiler import compile_infrastructure_obligation
from ovk.core.models import VerificationEvidence
from ovk.core.multi_lane import evaluate_lane
from ovk.core.policy_config import resolve_routing_config, routing_enforced_for_lane
from ovk.core.result_cache import (
    ControlPlaneResultCache,
    HardenedResultCache,
    cache_key,
    get_cached_evidence,
    store_cached_evidence,
)
from ovk.core.router import RoutingConfig, route_obligation, routing_config_from_policy
from ovk.core.self_protection_compiler import compile_self_protection_obligation
from ovk.core.shadow_obligation import build_shadow_obligation


def _control_plane(*, cache_dir: Path | None = None) -> BackendControlPlane:
    """Build an enforced/shadow control plane with hardened cache + worker."""
    hardened = HardenedResultCache(cache_dir / "control-plane") if cache_dir is not None else HardenedResultCache()
    return BackendControlPlane(
        cache=ControlPlaneResultCache(hardened),
        worker=LocalSubprocessWorker(),
        use_hardened_cache=True,
    )

LANE_TO_INTENT = {
    "self_protection": "agent-cannot-disable-own-ci-gate",
    "authorization": "no-admin-route-bypass",
    "infrastructure": "no-public-sensitive-resource",
    "ci_secrets": "no-secrets-in-untrusted-context",
    "deployment": "no-skipped-approval-state",
}


def _attach_execution_metadata(
    evidence: VerificationEvidence,
    *,
    lane: str,
    data: dict[str, Any],
    routing: dict[str, Any] | None,
    shadow_comparison: dict[str, Any] | None = None,
    intent_id: str | None = None,
    job_id: str | None = None,
    input_format: str | None = None,
) -> VerificationEvidence:
    """Record routing, input digest, and obligation-scoped evidence identity."""
    resolved_intent = intent_id or str((routing or {}).get("intent_id") or LANE_TO_INTENT.get(lane, lane))
    resolved_format = input_format or "infra"
    identity = {
        "intent_id": resolved_intent,
        "lane": lane,
        "input": data,
        "input_format": resolved_format,
        "job_id": job_id,
    }
    input_digest = content_digest({"lane": lane, "input": data})
    evidence_suffix = content_digest(identity)[:12]
    artifacts = list(evidence.generated_artifacts)
    artifacts.append({"kind": "input_digest", "digest": input_digest, "lane": lane})
    if routing is not None:
        artifacts.append(
            {
                "kind": "backend_routing",
                "intent_id": routing.get("intent_id"),
                "selected": routing.get("selected", []),
                "rejected": routing.get("rejected", []),
                "routing_id": routing.get("routing_id"),
                "routing_enforced": bool(routing.get("routing_enforced")),
                "executed_backends": [claim.backend for claim in evidence.backend_claims],
            }
        )
    if shadow_comparison is not None:
        artifacts.append(shadow_comparison)
    return evidence.model_copy(
        update={
            "evidence_id": f"{evidence.evidence_id}-{evidence_suffix}",
            "generated_artifacts": artifacts,
        }
    )


def _legacy_status_and_recommendation(evidence: VerificationEvidence) -> tuple[str, str]:
    status = evidence.backend_claims[0].status.value if evidence.backend_claims else "unknown"
    recommendation = str(evidence.decision.get("merge_recommendation", "require_human_review"))
    return status, recommendation


def _run_shadow_path(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    intent_id: str,
    policy: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Execute the typed control plane for comparison; never raises to legacy."""
    try:
        registry = build_default_lane_registry()
        obligation = build_shadow_obligation(
            lane=lane,
            data=data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            intent_id=intent_id,
        )
        budget = execution_budget_from_policy(policy)
        context = ExecutionContext(
            subject=obligation.subject,
            budget=budget,
            policy_digest=obligation.policy_digest,
            metadata={"shadow": True},
        )
        routing = route_obligation(obligation, registry, context=context, policy=policy)
        record = _control_plane().execute(obligation, routing, registry=registry)
        return {
            "record": record,
            "routing": routing,
        }
    except Exception as exc:  # noqa: BLE001 - shadow must not affect legacy authority
        return {
            "error": {
                "category": type(exc).__name__,
                "message": str(exc),
            }
        }


def _run_enforced_self_protection(
    *,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationEvidence:
    """Execute self-protection through registry selection; result is authoritative."""
    registry = build_self_protection_registry()
    metadata_trusted = True
    if isinstance(policy, dict):
        trust = policy.get("trust", {})
        if isinstance(trust, dict) and "metadata_trusted" in trust:
            metadata_trusted = bool(trust.get("metadata_trusted"))
        routing = policy.get("routing", {})
        if isinstance(routing, dict) and "metadata_trusted" in routing:
            metadata_trusted = bool(routing.get("metadata_trusted"))
    obligation = compile_self_protection_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        metadata_trusted=metadata_trusted,
    )
    # Untrusted metadata cannot produce allow under enforcement.
    if not metadata_trusted and obligation.coverage.status != "complete":
        pass
    budget = execution_budget_from_policy(policy)
    routing_config = routing_config_from_policy(policy)
    context = ExecutionContext(
        subject=obligation.subject,
        budget=budget,
        policy_digest=obligation.policy_digest,
        metadata={"enforced": True, "lane": "self_protection", "metadata_trusted": metadata_trusted},
    )
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(
            mode="enforced",
            strategy=routing_config.strategy,
            aggregation=routing_config.aggregation,
            max_selected_backends=routing_config.max_selected_backends,
            prefer_deterministic=routing_config.prefer_deterministic,
            allow_fallback=routing_config.allow_fallback,
            accept_partial_primary=routing_config.accept_partial_primary,
            enforced_lanes=frozenset({"self_protection"}),
        ),
        policy=policy,
    )
    record = _control_plane().execute(obligation, routing, registry=registry)
    evidence = execution_record_to_evidence(
        record,
        author_type=str((data.get("actor") or {}).get("type", data.get("author_type", "unknown"))),
        agent=str((data.get("actor") or {}).get("id", data.get("agent", "unknown"))),
        task=str(data.get("task", "unknown")),
        routing_enforced=True,
        schema_version="ovk.evidence.v2",
    )
    if not metadata_trusted and evidence.decision.get("merge_recommendation") == "allow":
        evidence = evidence.model_copy(
            update={
                "decision": {
                    **evidence.decision,
                    "merge_recommendation": "require_human_review",
                    "human_review_required": True,
                    "reason": "untrusted metadata cannot authorize allow under enforcement",
                    "fallback_accepted": False,
                }
            }
        )
    return evidence


def _run_enforced_authorization(
    *,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationEvidence:
    """Execute authorization through registry selection; result is authoritative."""
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
    )
    budget = execution_budget_from_policy(policy)
    routing_config = routing_config_from_policy(policy)
    context = ExecutionContext(
        subject=obligation.subject,
        budget=budget,
        policy_digest=obligation.policy_digest,
        metadata={"enforced": True, "lane": "authorization"},
    )
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(
            mode="enforced",
            strategy=routing_config.strategy,
            aggregation=routing_config.aggregation,
            max_selected_backends=routing_config.max_selected_backends,
            prefer_deterministic=routing_config.prefer_deterministic,
            allow_fallback=routing_config.allow_fallback,
            accept_partial_primary=routing_config.accept_partial_primary,
            enforced_lanes=frozenset({"authorization"}),
        ),
        policy=policy,
    )
    record = _control_plane().execute(obligation, routing, registry=registry)
    return execution_record_to_evidence(
        record,
        author_type=str(data.get("author_type", "unknown")),
        agent=str(data.get("agent", "unknown")),
        task=str(data.get("task", "unknown")),
        routing_enforced=True,
        schema_version="ovk.evidence.v2",
    )


def _run_enforced_lane(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
    registry_builder,
    compiler,
) -> VerificationEvidence:
    """Execute a lane through registry selection; result is authoritative."""
    registry = registry_builder()
    try:
        obligation = compiler(
            data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            policy=policy,
        )
    except TypeError:
        obligation = compiler(
            data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
        )
    budget = execution_budget_from_policy(policy)
    routing_config = routing_config_from_policy(policy)
    context = ExecutionContext(
        subject=obligation.subject,
        budget=budget,
        policy_digest=obligation.policy_digest,
        metadata={"enforced": True, "lane": lane},
    )
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(
            mode="enforced",
            strategy=routing_config.strategy,
            aggregation=routing_config.aggregation,
            max_selected_backends=routing_config.max_selected_backends,
            prefer_deterministic=routing_config.prefer_deterministic,
            allow_fallback=routing_config.allow_fallback,
            accept_partial_primary=routing_config.accept_partial_primary,
            enforced_lanes=frozenset({lane}),
        ),
        policy=policy,
    )
    record = _control_plane().execute(obligation, routing, registry=registry)
    return execution_record_to_evidence(
        record,
        author_type=str(data.get("author_type", "unknown")),
        agent=str(data.get("agent", "unknown")),
        task=str(data.get("task", "unknown")),
        routing_enforced=True,
        schema_version="ovk.evidence.v2",
    )


def _run_enforced_infrastructure(
    *,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationEvidence:
    return _run_enforced_lane(
        lane="infrastructure",
        data=data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
        registry_builder=build_infrastructure_registry,
        compiler=compile_infrastructure_obligation,
    )


def _run_enforced_ci_secrets(
    *,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationEvidence:
    return _run_enforced_lane(
        lane="ci_secrets",
        data=data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
        registry_builder=build_ci_secrets_registry,
        compiler=compile_ci_secrets_obligation,
    )


def _run_enforced_deployment(
    *,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
) -> VerificationEvidence:
    return _run_enforced_lane(
        lane="deployment",
        data=data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
        registry_builder=build_deployment_registry,
        compiler=compile_deployment_obligation,
    )


def _evaluate_obligation(
    obligation: dict[str, Any],
    *,
    routing_by_intent: dict[str, dict[str, Any]],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    cache_dir: Path | None,
    use_cache: bool,
    policy: dict[str, Any] | None = None,
) -> VerificationEvidence:
    lane = str(obligation["lane"])
    data = obligation["input"]
    intent_id = str(obligation.get("intent_id") or LANE_TO_INTENT.get(lane, lane))
    key = cache_key(lane, data)
    if use_cache and cache_dir is not None:
        cached = get_cached_evidence(cache_dir, key)
        if cached is not None:
            evidence = VerificationEvidence.model_validate(cached)
            return _attach_execution_metadata(
                evidence,
                lane=lane,
                data=data,
                routing=routing_by_intent.get(intent_id),
                intent_id=intent_id,
                job_id=obligation.get("job_id"),
                input_format=str(obligation.get("input_format", "infra")),
            )

    # Vertical slices: enforced control plane is authoritative.
    enforced_runners = {
        "authorization": _run_enforced_authorization,
        "self_protection": _run_enforced_self_protection,
        "infrastructure": _run_enforced_infrastructure,
        "ci_secrets": _run_enforced_ci_secrets,
        "deployment": _run_enforced_deployment,
    }
    if lane in enforced_runners and routing_enforced_for_lane(policy, lane):
        evidence = enforced_runners[lane](
            data=data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            policy=policy,
        )
        if use_cache and cache_dir is not None:
            store_cached_evidence(cache_dir, key, evidence.model_dump(mode="json"))
        return _attach_execution_metadata(
            evidence,
            lane=lane,
            data=data,
            routing=routing_by_intent.get(intent_id),
            intent_id=intent_id,
            job_id=obligation.get("job_id"),
            input_format=str(obligation.get("input_format", "infra")),
        )

    # Legacy path remains authoritative for non-enforced lanes.
    evidence = evaluate_lane(
        lane,
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        input_format=str(obligation.get("input_format", "infra")),
        policy_path=Path(obligation["policy_path"]) if obligation.get("policy_path") else None,
    )

    shadow_comparison: dict[str, Any] | None = None
    routing_config = resolve_routing_config(policy)
    if routing_config.mode in {"shadow", "enforced"} and lane in {
        "self_protection",
        "authorization",
        "infrastructure",
        "ci_secrets",
        "deployment",
    }:
        shadow = _run_shadow_path(
            lane=lane,
            data=data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            intent_id=intent_id,
            policy=policy,
        )
        if shadow and "record" in shadow:
            legacy_status, legacy_recommendation = _legacy_status_and_recommendation(evidence)
            shadow_comparison = compare_shadow_to_legacy(
                shadow=shadow["record"],
                legacy_status=legacy_status,
                legacy_recommendation=legacy_recommendation,
            )
            shadow_comparison["routing_mode"] = routing_config.mode
            shadow_comparison["legacy_authoritative"] = True
        elif shadow and "error" in shadow:
            shadow_comparison = {
                "kind": "shadow_comparison",
                "agreement": False,
                "error": shadow["error"],
                "legacy_authoritative": True,
                "routing_mode": routing_config.mode,
            }

    if use_cache and cache_dir is not None:
        store_cached_evidence(cache_dir, key, evidence.model_dump(mode="json"))
    return _attach_execution_metadata(
        evidence,
        lane=lane,
        data=data,
        routing=routing_by_intent.get(intent_id),
        shadow_comparison=shadow_comparison,
        intent_id=intent_id,
        job_id=obligation.get("job_id"),
        input_format=str(obligation.get("input_format", "infra")),
    )


def execute_obligations(
    obligations: list[dict[str, Any]],
    routing_by_intent: dict[str, dict[str, Any]],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    parallel: bool = True,
    policy: dict[str, Any] | None = None,
) -> list[VerificationEvidence]:
    """Evaluate obligations in parallel when configured.

    When ``policy.routing.mode`` is ``shadow``, the typed control plane also runs
    and a comparison artifact is attached. Legacy lane evaluation remains
    authoritative for the returned evidence decision.
    """
    if not obligations:
        return []
    if parallel and len(obligations) > 1:
        with ThreadPoolExecutor(max_workers=min(len(obligations), 5)) as pool:
            futures = [
                pool.submit(
                    _evaluate_obligation,
                    obligation,
                    routing_by_intent=routing_by_intent,
                    repo=repo,
                    head_sha=head_sha,
                    base_sha=base_sha,
                    cache_dir=cache_dir,
                    use_cache=use_cache,
                    policy=policy,
                )
                for obligation in obligations
            ]
            return [future.result() for future in futures]

    return [
        _evaluate_obligation(
            obligation,
            routing_by_intent=routing_by_intent,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            cache_dir=cache_dir,
            use_cache=use_cache,
            policy=policy,
        )
        for obligation in obligations
    ]
