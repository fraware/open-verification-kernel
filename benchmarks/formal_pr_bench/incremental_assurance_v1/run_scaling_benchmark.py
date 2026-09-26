"""Work-count benchmark for incremental Protected Effect assurance."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.incremental_protected_effect_execution import (
    execute_incremental_protected_effect_assurance,
)
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.protected_effect_evidence import (
    ProtectedEffectEvidenceCache,
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.resource_identity import ResourceIdentityTerm
from ovk.core.result_cache import HardenedResultCache


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_assurance_v1/scaling_workloads.json"
)
BENCHMARK_KEY = b"ovk-incremental-scaling-development-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="benchmark.incremental.scaling",
        extractor_version="0.1.0",
    )


def build_assurance_surface(
    size: int,
    *,
    head_sha: str,
) -> AssuranceIR:
    if size < 1:
        raise ValueError("assurance surface size must be positive")

    principal = PrincipalRef(
        principal_id="p:user",
        symbol="user",
        origin=_origin("routes.py"),
    )
    resources: list[ResourceRef] = []
    effects: list[EffectRef] = []
    guards: list[AuthorizationGuard] = []
    protected: list[ProtectedEffect] = []
    paths: list[SemanticPath] = []

    for index in range(size):
        resource_id = f"r:item-{index}"
        effect_id = f"e:item-{index}"
        guard_id = f"g:item-{index}"
        protected_id = f"pe:item-{index}"
        path_id = f"path:item-{index}"
        source_path = f"features/item_{index}.py"

        resources.append(
            ResourceRef(
                resource_id=resource_id,
                symbol=f"item_{index}_id",
                identity_term=ResourceIdentityTerm.symbol(f"item_{index}_id"),
                origin=_origin(source_path),
            )
        )
        effects.append(
            EffectRef(
                effect_id=effect_id,
                name=f"benchmark.item_{index}.read",
                origin=_origin(source_path),
            )
        )
        guards.append(
            AuthorizationGuard(
                guard_id=guard_id,
                principal_id=principal.principal_id,
                effect_id=effect_id,
                resource_id=resource_id,
                origin=_origin(source_path),
            )
        )
        protected.append(
            ProtectedEffect(
                protected_effect_id=protected_id,
                principal_id=principal.principal_id,
                effect_id=effect_id,
                resource_id=resource_id,
                origin=_origin(source_path),
            )
        )
        paths.append(
            SemanticPath(
                path_id=path_id,
                entrypoint=f"GET /items/{index}",
                guard_ids=[guard_id],
                protected_effect_ids=[protected_id],
                origin=_origin(source_path),
            )
        )

    return AssuranceIR(
        subject=VerificationSubject(
            repo="benchmark/incremental-scaling",
            base_sha="base",
            head_sha=head_sha,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="benchmark.incremental.scaling",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        principals=[principal],
        resources=resources,
        effects=effects,
        guards=guards,
        protected_effects=protected,
        paths=paths,
    )


def runtime_fingerprint() -> ProtectedEffectRuntimeFingerprint:
    return ProtectedEffectRuntimeFingerprint(
        environment_digest="env:incremental-scaling-v1",
        tool_digest="tool:protected-effect-v1",
        worker_image_digest="sha256:incremental-scaling-worker",
        native_execution=True,
    )


def _runtime_provider(_effect_id: str) -> ProtectedEffectRuntimeFingerprint:
    return runtime_fingerprint()


def seed_authenticated_cache(
    cache: ProtectedEffectEvidenceCache,
    ir: AssuranceIR,
) -> int:
    evaluations = evaluate_protected_effect_integrity(ir)
    runtime = runtime_fingerprint()

    for evaluation in evaluations:
        full = build_execution_fingerprint(
            evaluation,
            environment_digest=runtime.environment_digest,
            tool_digest=runtime.tool_digest,
            worker_image_digest=runtime.worker_image_digest,
            native_execution=runtime.native_execution,
        )
        evidence = protected_effect_evaluation_to_evidence(
            ir,
            evaluation,
            policy_digest="policy:incremental-scaling-v1",
            execution_fingerprint=full,
            signing_key=BENCHMARK_KEY,
        )
        cache.put(
            ir=ir,
            protected_effect_id=evaluation.protected_effect_id,
            policy_digest="policy:incremental-scaling-v1",
            execution_fingerprint=full,
            evidence=evidence,
            signature_key=BENCHMARK_KEY,
        )

    return len(evaluations)


def _counting_evaluator(counter: list[int]):
    def evaluate(ir: AssuranceIR, *, protected_effect_ids=None):
        requested = list(protected_effect_ids or [])
        counter.append(len(requested))
        return evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=requested,
        )

    return evaluate


def run_scaling_case(size: int) -> dict[str, float | int]:
    base = build_assurance_surface(size, head_sha=f"base-{size}")
    head = deepcopy(base)
    head.subject.head_sha = f"head-{size}"

    changed = next(
        resource for resource in head.resources if resource.resource_id == "r:item-0"
    )
    changed.identity_term = ResourceIdentityTerm.symbol("changed_item_0_id")

    with TemporaryDirectory(prefix="ovk-incremental-cold-") as cold_dir:
        cold_counter: list[int] = []
        cold = execute_incremental_protected_effect_assurance(
            base,
            head,
            policy_digest="policy:incremental-scaling-v1",
            runtime_fingerprint_provider=_runtime_provider,
            evidence_cache=ProtectedEffectEvidenceCache(
                HardenedResultCache(Path(cold_dir))
            ),
            signature_key=BENCHMARK_KEY,
            signing_key=BENCHMARK_KEY,
            evaluator=_counting_evaluator(cold_counter),
        )
        cold_fresh = sum(cold_counter)
        if len(cold.evidence) != size:
            raise AssertionError("cold execution did not cover the full assurance surface")

    with TemporaryDirectory(prefix="ovk-incremental-warm-") as warm_dir:
        warm_cache = ProtectedEffectEvidenceCache(
            HardenedResultCache(Path(warm_dir))
        )
        seed_checks = seed_authenticated_cache(warm_cache, base)
        warm_counter: list[int] = []
        warm = execute_incremental_protected_effect_assurance(
            base,
            head,
            policy_digest="policy:incremental-scaling-v1",
            runtime_fingerprint_provider=_runtime_provider,
            evidence_cache=warm_cache,
            signature_key=BENCHMARK_KEY,
            signing_key=BENCHMARK_KEY,
            evaluator=_counting_evaluator(warm_counter),
        )
        warm_fresh = sum(warm_counter)
        warm_reused = len(warm.reused_effects)
        if len(warm.evidence) != size:
            raise AssertionError("warm execution did not cover the full assurance surface")

    avoided = cold_fresh - warm_fresh
    avoided_fraction = avoided / cold_fresh if cold_fresh else 0.0

    return {
        "protected_effects": size,
        "initial_seed_checks": seed_checks,
        "cold_fresh_checks": cold_fresh,
        "warm_fresh_checks": warm_fresh,
        "warm_reused_checks": warm_reused,
        "avoided_checks": avoided,
        "avoided_fraction": avoided_fraction,
    }


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def run_scaling_benchmark() -> dict:
    config = load_config()
    results = [
        run_scaling_case(int(size))
        for size in config["sizes"]
    ]
    return {
        "schema_version": config["schema_version"],
        "benchmark_id": config["benchmark_id"],
        "metric": config["metric"],
        "claim_scope": config["claim_scope"],
        "results": results,
    }


def main() -> None:
    print(json.dumps(run_scaling_benchmark(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
