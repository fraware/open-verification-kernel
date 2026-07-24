"""Execute compiled obligations through lane adapters with routing metadata.



Shadow mode runs the typed control plane beside legacy ``evaluate_lane``;

legacy evidence remains authoritative unless a lane is policy-enforced.

"""

from __future__ import annotations


from concurrent.futures import ThreadPoolExecutor

from pathlib import Path

from typing import Any, Mapping


from ovk.adapters.authorization import build_authorization_registry

from ovk.adapters.ci_secrets import build_ci_secrets_registry

from ovk.adapters.deployment import build_deployment_registry

from ovk.adapters.infrastructure import build_infrastructure_registry

from ovk.adapters.lane import build_default_lane_registry

from ovk.adapters.self_protection import build_self_protection_registry

from ovk.core.backend_control_plane import BackendControlPlane, compare_shadow_to_legacy

from ovk.core.bundle import content_digest

from ovk.core.evidence_from_execution import execution_record_to_evidence

from ovk.core.execution_budget import LocalSubprocessWorker, execution_budget_from_policy

from ovk.core.execution_models import ExecutionContext, RoutingDecision, VerificationObligation

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

from ovk.core.router import route_obligation, routing_decision_to_legacy_dict

from ovk.core.routing_pipeline import (
    AuthoritativeRoutingPlan,
    ensure_authoritative_routing,
    intent_id_for_obligation,
    require_routing_decision,
)

from ovk.core.self_protection_compiler import resolve_metadata_trusted

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


_LANE_REGISTRY_BUILDERS = {
    "authorization": build_authorization_registry,
    "self_protection": build_self_protection_registry,
    "infrastructure": build_infrastructure_registry,
    "ci_secrets": build_ci_secrets_registry,
    "deployment": build_deployment_registry,
}


def _routing_metadata(
    routing: RoutingDecision | Mapping[str, Any] | None,
    *,
    intent_id: str,
    routing_enforced: bool,
) -> dict[str, Any] | None:

    if routing is None:
        return None

    if isinstance(routing, RoutingDecision):
        payload = routing_decision_to_legacy_dict(routing, intent_id=intent_id)

    else:
        payload = dict(routing)

    payload["routing_enforced"] = routing_enforced

    return payload


def _attach_execution_metadata(
    evidence: VerificationEvidence,
    *,
    lane: str,
    data: dict[str, Any],
    routing: RoutingDecision | Mapping[str, Any] | None,
    shadow_comparison: dict[str, Any] | None = None,
    intent_id: str | None = None,
    job_id: str | None = None,
    input_format: str | None = None,
    routing_enforced: bool = False,
) -> VerificationEvidence:
    """Record routing, input digest, and obligation-scoped evidence identity."""

    resolved_intent = (
        intent_id
        or str((routing or {}).get("intent_id") if isinstance(routing, dict) else None)
        or LANE_TO_INTENT.get(lane, lane)
    )

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

    metadata = _routing_metadata(routing, intent_id=resolved_intent, routing_enforced=routing_enforced)

    if metadata is not None:
        artifacts.append(
            {
                "kind": "backend_routing",
                "intent_id": metadata.get("intent_id", resolved_intent),
                "selected": metadata.get("selected", []),
                "rejected": metadata.get("rejected", []),
                "routing_id": metadata.get("routing_id") or evidence.routing_id,
                "routing_enforced": routing_enforced,
                "executed_backends": [claim.backend for claim in evidence.backend_claims],
            }
        )

    if shadow_comparison is not None:
        artifacts.append(shadow_comparison)

    return evidence.model_copy(
        update={
            "evidence_id": f"{evidence.evidence_id}-{evidence_suffix}",
            "generated_artifacts": artifacts,
            "routing_id": evidence.routing_id or (metadata or {}).get("routing_id"),
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


def _run_enforced_with_routing(
    *,
    lane: str,
    data: dict[str, Any],
    routing: RoutingDecision,
    typed_obligation: VerificationObligation,
    policy: dict[str, Any] | None,
    schema_version: str,
) -> VerificationEvidence:
    """Execute one enforced lane using a pre-computed immutable routing decision."""

    registry_builder = _LANE_REGISTRY_BUILDERS.get(lane)

    if registry_builder is None:
        raise RuntimeError(f"no enforced registry for lane {lane!r}")

    registry = registry_builder()

    record = _control_plane().execute(typed_obligation, routing, registry=registry)

    evidence = execution_record_to_evidence(
        record,
        author_type=str((data.get("actor") or {}).get("type", data.get("author_type", "unknown"))),
        agent=str((data.get("actor") or {}).get("id", data.get("agent", "unknown"))),
        task=str(data.get("task", "unknown")),
        routing_enforced=True,
        schema_version=schema_version,
    )

    if lane == "self_protection":
        metadata_trusted = resolve_metadata_trusted(policy)

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


def _evaluate_obligation(
    obligation: dict[str, Any],
    *,
    routing_plan: AuthoritativeRoutingPlan,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    cache_dir: Path | None,
    use_cache: bool,
    policy: dict[str, Any] | None = None,
    evidence_schema_version: str = "ovk.evidence.v3",
) -> VerificationEvidence:

    lane = str(obligation["lane"])

    data = obligation["input"]

    intent_id = intent_id_for_obligation(obligation)

    input_format = str(obligation.get("input_format", "infra"))

    key = cache_key(
        lane,
        data,
        subject={"repo": repo, "head_sha": head_sha, **({"base_sha": base_sha} if base_sha else {})},
        execution_fingerprint={"intent_id": intent_id, "input_format": input_format},
    )

    precomputed_routing = routing_plan.routing_by_intent.get(intent_id)

    precomputed_typed = routing_plan.typed_obligations.get(intent_id)

    if use_cache and cache_dir is not None:
        cached = get_cached_evidence(cache_dir, key)

        if cached is not None:
            evidence = VerificationEvidence.model_validate(cached)

            return _attach_execution_metadata(
                evidence,
                lane=lane,
                data=data,
                routing=precomputed_routing,
                intent_id=intent_id,
                job_id=obligation.get("job_id"),
                input_format=input_format,
                routing_enforced=routing_enforced_for_lane(policy, lane),
            )

    if routing_enforced_for_lane(policy, lane):
        routing_decision = require_routing_decision(
            precomputed_routing,
            intent_id=intent_id,
            lane=lane,
            policy=policy,
        )

        if precomputed_typed is None:
            raise RuntimeError(f"missing typed obligation for enforced intent {intent_id!r}")

        evidence = _run_enforced_with_routing(
            lane=lane,
            data=data,
            routing=routing_decision,
            typed_obligation=precomputed_typed,
            policy=policy,
            schema_version=evidence_schema_version,
        )

        if use_cache and cache_dir is not None:
            store_cached_evidence(cache_dir, key, evidence.model_dump(mode="json"))

        return _attach_execution_metadata(
            evidence,
            lane=lane,
            data=data,
            routing=routing_decision,
            intent_id=intent_id,
            job_id=obligation.get("job_id"),
            input_format=input_format,
            routing_enforced=True,
        )

    evidence = evaluate_lane(
        lane,
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        input_format=input_format,
        policy_path=Path(obligation["policy_path"]) if obligation.get("policy_path") else None,
    )

    shadow_comparison: dict[str, Any] | None = None

    routing_config = resolve_routing_config(policy)

    if routing_config.mode in {"shadow", "enforced"} and lane in _LANE_REGISTRY_BUILDERS:
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
        routing=precomputed_routing,
        shadow_comparison=shadow_comparison,
        intent_id=intent_id,
        job_id=obligation.get("job_id"),
        input_format=input_format,
        routing_enforced=False,
    )


def execute_obligations(
    obligations: list[dict[str, Any]],
    routing_by_intent: Mapping[str, RoutingDecision | Mapping[str, Any] | None] | None = None,
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    parallel: bool = True,
    policy: dict[str, Any] | None = None,
    evidence_schema_version: str = "ovk.evidence.v3",
) -> list[VerificationEvidence]:
    """Evaluate obligations using one authoritative routing decision per intent."""

    if not obligations:
        return []

    routing_plan = ensure_authoritative_routing(
        obligations,
        routing_by_intent,
        policy=policy,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )

    if parallel and len(obligations) > 1:
        with ThreadPoolExecutor(max_workers=min(len(obligations), 5)) as pool:
            futures = [
                pool.submit(
                    _evaluate_obligation,
                    obligation,
                    routing_plan=routing_plan,
                    repo=repo,
                    head_sha=head_sha,
                    base_sha=base_sha,
                    cache_dir=cache_dir,
                    use_cache=use_cache,
                    policy=policy,
                    evidence_schema_version=evidence_schema_version,
                )
                for obligation in obligations
            ]

            return [future.result() for future in futures]

    return [
        _evaluate_obligation(
            obligation,
            routing_plan=routing_plan,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            cache_dir=cache_dir,
            use_cache=use_cache,
            policy=policy,
            evidence_schema_version=evidence_schema_version,
        )
        for obligation in obligations
    ]
