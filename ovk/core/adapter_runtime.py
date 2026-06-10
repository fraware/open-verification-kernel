"""Execute compiled obligations through lane adapters with routing metadata."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ovk.core.models import VerificationEvidence
from ovk.core.multi_lane import evaluate_lane
from ovk.core.result_cache import cache_key, get_cached_evidence, store_cached_evidence

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
) -> VerificationEvidence:
    """Record routing decisions and input digest on evidence artifacts."""
    artifacts = list(evidence.generated_artifacts)
    artifacts.append({"kind": "input_digest", "digest": cache_key(lane, data), "lane": lane})
    if routing is not None:
        artifacts.append(
            {
                "kind": "backend_routing",
                "intent_id": routing.get("intent_id"),
                "selected": routing.get("selected", []),
                "rejected": routing.get("rejected", []),
            }
        )
    return evidence.model_copy(update={"generated_artifacts": artifacts})


def _evaluate_obligation(
    obligation: dict[str, Any],
    *,
    routing_by_intent: dict[str, dict[str, Any]],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    cache_dir: Path | None,
    use_cache: bool,
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
            )

    evidence = evaluate_lane(
        lane,
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        input_format=str(obligation.get("input_format", "infra")),
        policy_path=Path(obligation["policy_path"]) if obligation.get("policy_path") else None,
    )
    if use_cache and cache_dir is not None:
        store_cached_evidence(cache_dir, key, evidence.model_dump(mode="json"))
    return _attach_execution_metadata(
        evidence,
        lane=lane,
        data=data,
        routing=routing_by_intent.get(intent_id),
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
) -> list[VerificationEvidence]:
    """Evaluate obligations in parallel when configured."""
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
        )
        for obligation in obligations
    ]
