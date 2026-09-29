"""Incremental Protected Effect execution with strict evidence reuse.

Cache reuse is an optimization only. Every protected effect that does not
produce an eligible authenticated cache hit is freshly evaluated.

The execution layer never promotes Protected Effect evidence into a controlling
merge decision; fresh and reused records remain shadow evidence.
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, Field

from ovk.core.assurance_ir import AssuranceIR
from ovk.core.incremental_assurance import (
    IncrementalAssurancePlan,
    plan_incremental_assurance,
)
from ovk.core.models import VerificationEvidence
from ovk.core.protected_effect_evaluation import (
    ProtectedEffectIntegrityEvaluation,
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_evidence import (
    ProtectedEffectEvidenceCache,
    ProtectedEffectExecutionFingerprint,
    ProtectedEffectReusePolicy,
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)


RuntimeFingerprintProvider = Callable[
    [str],
    ProtectedEffectRuntimeFingerprint | None,
]
ProtectedEffectEvaluator = Callable[..., list[ProtectedEffectIntegrityEvaluation]]


class IncrementalProtectedEffectExecution(BaseModel):
    """Auditable result of one incremental Protected Effect execution."""

    plan: IncrementalAssurancePlan
    fresh_effects: list[str] = Field(default_factory=list)
    reused_effects: list[str] = Field(default_factory=list)
    cache_miss_effects: list[str] = Field(default_factory=list)
    cache_miss_reasons: dict[str, str] = Field(default_factory=dict)
    fresh_evaluations: list[ProtectedEffectIntegrityEvaluation] = Field(default_factory=list)
    evidence: list[VerificationEvidence] = Field(default_factory=list)
    cache_store_failures: dict[str, str] = Field(default_factory=dict)
    cache_store_skipped: dict[str, str] = Field(default_factory=dict)


def _validate_plan(
    *,
    base: AssuranceIR,
    head: AssuranceIR,
    plan: IncrementalAssurancePlan,
) -> None:
    if plan.base_assurance_ir_digest != base.assurance_ir_digest:
        raise ValueError(
            "incremental assurance plan base digest does not match supplied base Assurance IR"
        )
    if plan.head_assurance_ir_digest != head.assurance_ir_digest:
        raise ValueError(
            "incremental assurance plan head digest does not match supplied head Assurance IR"
        )


def _runtime_for(
    provider: RuntimeFingerprintProvider,
    effect_id: str,
) -> ProtectedEffectRuntimeFingerprint | None:
    runtime = provider(effect_id)
    if runtime is not None and not isinstance(runtime, ProtectedEffectRuntimeFingerprint):
        raise TypeError(
            "runtime_fingerprint_provider must return "
            "ProtectedEffectRuntimeFingerprint or None"
        )
    return runtime


def _validate_fresh_results(
    *,
    head: AssuranceIR,
    requested: set[str],
    results: list[ProtectedEffectIntegrityEvaluation],
) -> dict[str, ProtectedEffectIntegrityEvaluation]:
    by_id: dict[str, ProtectedEffectIntegrityEvaluation] = {}
    duplicates: set[str] = set()

    for result in results:
        if result.protected_effect_id in by_id:
            duplicates.add(result.protected_effect_id)
        by_id[result.protected_effect_id] = result

    actual = set(by_id)
    if duplicates:
        raise ValueError(
            "fresh Protected Effect evaluator returned duplicate effect ids: "
            + ", ".join(sorted(duplicates))
        )
    if actual != requested:
        missing = sorted(requested - actual)
        unexpected = sorted(actual - requested)
        raise ValueError(
            "fresh Protected Effect evaluator result set mismatch; "
            f"missing={missing}; unexpected={unexpected}"
        )

    for effect_id, result in by_id.items():
        if result.assurance_ir_digest != head.assurance_ir_digest:
            raise ValueError(
                "fresh Protected Effect evaluation is bound to a different Assurance IR: "
                + effect_id
            )

    return by_id


def _full_execution_fingerprint(
    evaluation: ProtectedEffectIntegrityEvaluation,
    runtime: ProtectedEffectRuntimeFingerprint | None,
) -> ProtectedEffectExecutionFingerprint | None:
    if runtime is None:
        return None
    return build_execution_fingerprint(
        evaluation,
        environment_digest=runtime.environment_digest,
        tool_digest=runtime.tool_digest,
        worker_image_digest=runtime.worker_image_digest,
        native_execution=runtime.native_execution,
    )


def execute_incremental_protected_effect_assurance(
    base: AssuranceIR,
    head: AssuranceIR,
    *,
    policy_digest: str,
    runtime_fingerprint_provider: RuntimeFingerprintProvider,
    evidence_cache: ProtectedEffectEvidenceCache | None = None,
    plan: IncrementalAssurancePlan | None = None,
    reuse_policy: ProtectedEffectReusePolicy | None = None,
    signature_key: bytes | None = None,
    signing_key: bytes | None = None,
    evaluator: ProtectedEffectEvaluator = evaluate_protected_effect_integrity,
) -> IncrementalProtectedEffectExecution:
    """Reuse eligible evidence and freshly evaluate every remaining head effect.

    Reuse is attempted only for semantic reuse candidates. Any miss,
    ineligibility, missing runtime fingerprint, or absent cache moves the effect
    into the fresh set.

    Fresh PASS evidence is cached only when it has enough provenance to satisfy
    the configured reuse policy. Cache write failures are recorded and never
    suppress the freshly computed result.
    """

    policy_digest = policy_digest.strip()
    if not policy_digest:
        raise ValueError("policy_digest must be non-empty")

    resolved_plan = plan or plan_incremental_assurance(base, head)
    _validate_plan(base=base, head=head, plan=resolved_plan)

    cache = evidence_cache
    effective_reuse_policy = reuse_policy or ProtectedEffectReusePolicy()

    fresh_ids: set[str] = set(resolved_plan.reverify_effects)
    reused_ids: set[str] = set()
    cache_miss_ids: set[str] = set()
    cache_miss_reasons: dict[str, str] = {}
    evidence_by_effect: dict[str, VerificationEvidence] = {}
    runtime_by_effect: dict[str, ProtectedEffectRuntimeFingerprint | None] = {}

    for effect_id in sorted(resolved_plan.semantic_reuse_candidates):
        runtime = _runtime_for(runtime_fingerprint_provider, effect_id)
        runtime_by_effect[effect_id] = runtime

        if runtime is None:
            fresh_ids.add(effect_id)
            cache_miss_ids.add(effect_id)
            cache_miss_reasons[effect_id] = "runtime_fingerprint_unavailable"
            continue

        if cache is None:
            fresh_ids.add(effect_id)
            cache_miss_ids.add(effect_id)
            cache_miss_reasons[effect_id] = "evidence_cache_unavailable"
            continue

        reused = cache.reuse_for_head(
            head_ir=head,
            protected_effect_id=effect_id,
            policy_digest=policy_digest,
            current_runtime_fingerprint=runtime,
            reuse_policy=effective_reuse_policy,
            signature_key=signature_key,
            signing_key=signing_key,
        )
        if reused is None:
            fresh_ids.add(effect_id)
            cache_miss_ids.add(effect_id)
            cache_miss_reasons[effect_id] = "cache_miss_or_ineligible_evidence"
            continue

        reused_ids.add(effect_id)
        evidence_by_effect[effect_id] = reused

    fresh_results: list[ProtectedEffectIntegrityEvaluation] = []
    cache_store_failures: dict[str, str] = {}
    cache_store_skipped: dict[str, str] = {}

    if fresh_ids:
        fresh_results = evaluator(
            head,
            protected_effect_ids=sorted(fresh_ids),
        )
        by_id = _validate_fresh_results(
            head=head,
            requested=fresh_ids,
            results=fresh_results,
        )

        for effect_id in sorted(fresh_ids):
            evaluation = by_id[effect_id]
            runtime = runtime_by_effect.get(effect_id)
            if effect_id not in runtime_by_effect:
                runtime = _runtime_for(runtime_fingerprint_provider, effect_id)
                runtime_by_effect[effect_id] = runtime

            execution_fingerprint = _full_execution_fingerprint(
                evaluation,
                runtime,
            )
            fresh_evidence = protected_effect_evaluation_to_evidence(
                head,
                evaluation,
                policy_digest=policy_digest,
                execution_fingerprint=execution_fingerprint,
                signing_key=signing_key,
            )
            evidence_by_effect[effect_id] = fresh_evidence

            if evaluation.status != "pass":
                cache_store_skipped[effect_id] = "fresh evaluation is not PASS"
                continue
            if cache is None:
                cache_store_skipped[effect_id] = "evidence cache unavailable"
                continue
            if execution_fingerprint is None:
                cache_store_skipped[effect_id] = "runtime fingerprint unavailable"
                continue
            if effective_reuse_policy.require_signature and signing_key is None:
                cache_store_skipped[effect_id] = (
                    "reuse policy requires signed evidence but signing_key is unavailable"
                )
                continue

            try:
                cache.put(
                    ir=head,
                    protected_effect_id=effect_id,
                    policy_digest=policy_digest,
                    execution_fingerprint=execution_fingerprint,
                    evidence=fresh_evidence,
                    reuse_policy=effective_reuse_policy,
                    signature_key=(
                        signing_key
                        if signing_key is not None
                        else signature_key
                    ),
                )
            except Exception as exc:
                cache_store_failures[effect_id] = f"{type(exc).__name__}: {exc}"

    expected_head_effects = {
        effect.protected_effect_id
        for effect in head.protected_effects
    }
    represented = set(evidence_by_effect)
    if represented != expected_head_effects:
        raise ValueError(
            "incremental Protected Effect execution did not cover every head effect; "
            f"missing={sorted(expected_head_effects - represented)}; "
            f"unexpected={sorted(represented - expected_head_effects)}"
        )

    return IncrementalProtectedEffectExecution(
        plan=resolved_plan,
        fresh_effects=sorted(fresh_ids),
        reused_effects=sorted(reused_ids),
        cache_miss_effects=sorted(cache_miss_ids),
        cache_miss_reasons=dict(sorted(cache_miss_reasons.items())),
        fresh_evaluations=sorted(
            fresh_results,
            key=lambda item: item.protected_effect_id,
        ),
        evidence=[
            evidence_by_effect[effect_id]
            for effect_id in sorted(evidence_by_effect)
        ],
        cache_store_failures=dict(sorted(cache_store_failures.items())),
        cache_store_skipped=dict(sorted(cache_store_skipped.items())),
    )
