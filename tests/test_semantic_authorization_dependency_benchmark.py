from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity


CASE_PATH = Path(
    "benchmarks/formal_pr_bench/semantic_authorization_v2/"
    "praisonai_cross_workspace_dependency_reduced.json"
)


def _profile(raw: dict) -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects=dict(raw["sink_effects"]),
        sink_identity_args={
            str(key): int(value)
            for key, value in raw.get("sink_identity_args", {}).items()
        },
        sink_scope_keywords=dict(raw.get("sink_scope_keywords", {})),
        sink_missing_scope_unconstrained=frozenset(
            raw.get("sink_missing_scope_unconstrained", [])
        ),
        dependency_guard_resources=dict(
            raw.get("dependency_guard_resources", {})
        ),
        dependency_guard_effects={
            str(key): tuple(str(item) for item in value)
            for key, value in raw.get("dependency_guard_effects", {}).items()
        },
        principal_parameter=str(raw.get("principal_parameter", "user")),
    )


def _evaluate(source: str, profile: FastApiDependencyEffectProfile):
    materials = materials_from_pair(
        path="praisonai_platform/api/routes/agents.py",
        base_source=source,
        head_source=source,
        repo="benchmark/praisonai-platform-reduced",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert ir.coverage.status == "complete"
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return ir, results[0]


def test_public_dependency_service_reduction_detects_scope_regression() -> None:
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    profile = _profile(case["profile"])
    variants = {item["id"]: item for item in case["variants"]}

    vulnerable_ir, vulnerable = _evaluate(
        variants["vulnerable_unscoped_service_lookup"]["source"],
        profile,
    )
    secure_ir, secure = _evaluate(
        variants["secure_workspace_scoped_service_lookup"]["source"],
        profile,
    )

    assert len(vulnerable_ir.guards) == 1
    assert len(secure_ir.guards) == 1
    assert secure.status == "pass"

    secure_binding = secure_ir.resource_bindings[0]
    assert secure_binding.relation == "same_tenant"
    assert secure_binding.authorized_projection == "identity"
    assert secure_binding.acted_projection == "scope"

    if importlib.util.find_spec("z3") is None:
        assert vulnerable.status == "unknown"
        assert vulnerable.resource_binding_evidence[0].status == "unknown"
    else:
        assert vulnerable.status == "fail"
        evidence = vulnerable.resource_binding_evidence[0]
        assert evidence.status == "fail"
        assert evidence.counterexample is not None
        assert evidence.counterexample["relation"] == "same_tenant"
