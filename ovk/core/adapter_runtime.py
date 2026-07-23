"""Execute compiled obligations through legacy lanes or the typed control plane.

Legacy mode may use the flat evidence cache. Shadow and enforced modes rely on
the routing-bound hardened control-plane cache so policy or routing changes can
never reuse evidence from another execution regime.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

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
from ovk.core.execution_models import ExecutionContext, VerificationObligation
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

LANE_TO_INTENT = {
    "self_protection": "agent-cannot-disable-own-ci-gate",
    "authorization": "no-admin-route-bypass",
    "infrastructure": "no-public-sensitive-resource",
    "ci_secrets": "no-secrets-in-untrusted-context",
    "deployment": "no-skipped-approval-state",
}

RegistryBuilder = Callable[[], Any]
ObligationCompiler = Callable[..., VerificationObligation]


def _control_plane(*, cache_dir: Path | None = None) -> BackendControlPlane:
    """Build a control plane with a routing-bound hardened cache and worker."""
    hardened = (
        HardenedResultCache(cache_dir / "control-plane")
        if cache_dir is not None
        else HardenedResultCache()
    )
    return BackendControlPlane(
        cache=ControlPlaneResultCache(hardened),
        worker=LocalSubprocessWorker(),
        use_hardened_cache=True,
    )


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
    """Attach compatibility metadata without contradicting authoritative v2 routing."""
    resolved_intent = intent_id or str(
        (routing or {}).get("intent_id") or LANE_TO_INTENT.get(lane, lane)
    )
    resolved_format = input_format or "infra"
    input_digest = content_digest({"lane": lane, "input": data})
    artifacts = list(evidence.generated_artifacts)
    if not any(
        item.get("kind") == "input_digest" and item.get("digest") == input_digest
        for item in artifacts
        if isinstance(item, dict)
    ):
        artifacts.append({"kind": "input_digest", "digest": input_digest, "lane": lane})

    # Enforced evidence already contains the authoritative typed routing record.
    # A legacy capability-router artifact would create two conflicting stories.
    if routing is not None and evidence.routing_enforced is not True:
        artifacts.append(
            {
                "kind": "backend_routing",
                "intent_id": routing.get("intent_id"),
                "selected": routing.get("selected", []),
                "rejected": routing.get("rejected", []),
                "routing_id": routing.get("routing_id"),
                "routing_enforced": False,
                "executed_backends": [claim.backend for claim in evidence.backend_claims],
            }
        )
    if shadow_comparison is not None:
        artifacts.append(shadow_comparison)

    if evidence.routing_enforced is True:
        return evidence.model_copy(update={"generated_artifacts": artifacts})

    identity = {
        "intent_id": resolved_intent,
        "lane": lane,
        "input": data,
        "input_format": resolved_format,
        "job_id": job_id,
    }
    evidence_suffix = content_digest(identity)[:12]
    return evidence.model_copy(
        update={
            "evidence_id": f"{evidence.evidence_id}-{evidence_suffix}",
            "generated_artifacts": artifacts,
        }
    )


def _legacy_status_and_recommendation(evidence: VerificationEvidence) -> tuple[str, str]:
    status = evidence.backend_claims[0].status.value if evidence.backend_claims else "unknown"
    recommendation = str(
        evidence.decision.get("merge_recommendation", "require_human_review")
    )
    return status, recommendation


def _effective_policy_digest(
    policy: dict[str, Any] | None,
    policy_path: Path | None,
) -> str:
    lane_policy: dict[str, Any] | str | None = None
    if policy_path is not None and policy_path.is_file():
        try:
            lane_policy = policy_path.read_text(encoding="utf-8")
        except OSError:
            lane_policy = "unreadable"
    return content_digest({"repository_policy": policy or {}, "lane_policy": lane_policy})


def _routing_config_for_enforced(policy: dict[str, Any] | None, lane: str) -> RoutingConfig:
    current = routing_config_from_policy(policy)
    return RoutingConfig(
        mode="enforced",
        strategy=current.strategy,
        aggregation=current.aggregation,
        max_selected_backends=current.max_selected_backends,
        prefer_deterministic=current.prefer_deterministic,
        allow_fallback=current.allow_fallback,
        accept_partial_primary=current.accept_partial_primary,
        enforced_lanes=frozenset({lane}),
    )


def _run_shadow_path(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    intent_id: str,
    policy: dict[str, Any] | None,
    cache_dir: Path | None,
) -> dict[str, Any]:
    """Execute the typed lane-wrapper control plane for comparison only."""
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
        record = _control_plane(cache_dir=cache_dir).execute(
            obligation,
            routing,
            registry=registry,
        )
        return {"record": record, "routing": routing}
    except Exception as exc:  # noqa: BLE001 - shadow cannot affect legacy authority
        return {
            "error": {
                "category": type(exc).__name__,
                "message": str(exc),
            }
        }


def _compile_enforced_obligation(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
    policy_digest: str,
) -> tuple[Any, VerificationObligation, dict[str, str]]:
    if lane == "self_protection":
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
            policy_digest=policy_digest,
            metadata_trusted=metadata_trusted,
        )
        actor = data.get("actor") if isinstance(data.get("actor"), dict) else {}
        metadata = {
            "author_type": str(actor.get("type", data.get("author_type", "unknown"))),
            "agent": str(actor.get("id", data.get("agent", "unknown"))),
            "task": str(data.get("task", "unknown")),
            "metadata_trusted": str(metadata_trusted),
        }
        return registry, obligation, metadata

    builders: dict[str, tuple[RegistryBuilder, ObligationCompiler]] = {
        "authorization": (build_authorization_registry, compile_authorization_obligation),
        "infrastructure": (build_infrastructure_registry, compile_infrastructure_obligation),
        "ci_secrets": (build_ci_secrets_registry, compile_ci_secrets_obligation),
        "deployment": (build_deployment_registry, compile_deployment_obligation),
    }
    registry_builder, compiler = builders[lane]
    registry = registry_builder()
    obligation = compiler(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy_digest=policy_digest,
        policy=policy,
    )
    metadata = {
        "author_type": str(data.get("author_type", "unknown")),
        "agent": str(data.get("agent", "unknown")),
        "task": str(data.get("task", "unknown")),
    }
    return registry, obligation, metadata


def _run_enforced_lane(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    policy: dict[str, Any] | None,
    policy_digest: str,
    cache_dir: Path | None,
) -> VerificationEvidence:
    registry, obligation, metadata = _compile_enforced_obligation(
        lane=lane,
        data=data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=policy,
        policy_digest=policy_digest,
    )
    budget = execution_budget_from_policy(policy)
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
        config=_routing_config_for_enforced(policy, lane),
        policy=policy,
    )
    record = _control_plane(cache_dir=cache_dir).execute(
        obligation,
        routing,
        registry=registry,
    )
    evidence = execution_record_to_evidence(
        record,
        author_type=metadata["author_type"],
        agent=metadata["agent"],
        task=metadata["task"],
        routing_enforced=True,
        schema_version="ovk.evidence.v2",
    )
    if (
        lane == "self_protection"
        and metadata.get("metadata_trusted") == "False"
        and evidence.decision.get("merge_recommendation") == "allow"
    ):
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
    input_format = str(obligation.get("input_format", "infra"))
    policy_path = Path(obligation["policy_path"]) if obligation.get("policy_path") else None
    routing_config = resolve_routing_config(policy)
    enforced = lane in LANE_TO_INTENT and routing_enforced_for_lane(policy, lane)
    legacy_cache_allowed = routing_config.mode == "legacy" and not enforced
    policy_digest = _effective_policy_digest(policy, policy_path)

    key = cache_key(
        lane,
        data,
        policy_digest=policy_digest,
        subject={
            "repo": repo,
            "head_sha": head_sha,
            **({"base_sha": base_sha} if base_sha else {}),
        },
        execution_fingerprint={
            "intent_id": intent_id,
            "input_format": input_format,
            "routing_mode": routing_config.mode,
        },
    )
    if legacy_cache_allowed and use_cache and cache_dir is not None:
        cached = get_cached_evidence(cache_dir, key)
        if cached is not None:
            return _attach_execution_metadata(
                VerificationEvidence.model_validate(cached),
                lane=lane,
                data=data,
                routing=routing_by_intent.get(intent_id),
                intent_id=intent_id,
                job_id=obligation.get("job_id"),
                input_format=input_format,
            )

    if enforced:
        evidence = _run_enforced_lane(
            lane=lane,
            data=data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            policy=policy,
            policy_digest=policy_digest,
            cache_dir=cache_dir if use_cache else None,
        )
        return _attach_execution_metadata(
            evidence,
            lane=lane,
            data=data,
            routing=None,
            intent_id=intent_id,
            job_id=obligation.get("job_id"),
            input_format=input_format,
        )

    evidence = evaluate_lane(
        lane,
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        input_format=input_format,
        policy_path=policy_path,
    )

    shadow_comparison: dict[str, Any] | None = None
    if routing_config.mode in {"shadow", "enforced"} and lane in LANE_TO_INTENT:
        shadow = _run_shadow_path(
            lane=lane,
            data=data,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            intent_id=intent_id,
            policy=policy,
            cache_dir=cache_dir if use_cache else None,
        )
        if "record" in shadow:
            legacy_status, legacy_recommendation = _legacy_status_and_recommendation(evidence)
            shadow_comparison = compare_shadow_to_legacy(
                shadow=shadow["record"],
                legacy_status=legacy_status,
                legacy_recommendation=legacy_recommendation,
            )
            shadow_comparison["routing_mode"] = routing_config.mode
            shadow_comparison["legacy_authoritative"] = True
        else:
            shadow_comparison = {
                "kind": "shadow_comparison",
                "agreement": False,
                "error": shadow.get("error", {"message": "shadow execution failed"}),
                "legacy_authoritative": True,
                "routing_mode": routing_config.mode,
            }

    if legacy_cache_allowed and use_cache and cache_dir is not None:
        store_cached_evidence(cache_dir, key, evidence.model_dump(mode="json"))
    return _attach_execution_metadata(
        evidence,
        lane=lane,
        data=data,
        routing=routing_by_intent.get(intent_id),
        shadow_comparison=shadow_comparison,
        intent_id=intent_id,
        job_id=obligation.get("job_id"),
        input_format=input_format,
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
    """Evaluate obligations while preserving deterministic submission order."""
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
