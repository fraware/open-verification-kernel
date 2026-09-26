from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi import (
    FastApiProtectedEffectExtractor,
    ProtectedEffectProfile,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity


CASE_PATH = Path(
    "benchmarks/formal_pr_bench/semantic_authorization_v1/"
    "praisonai_cross_workspace_idor_reduced.json"
)


def _profile(raw: dict) -> ProtectedEffectProfile:
    return ProtectedEffectProfile(
        sink_effects=dict(raw["sink_effects"]),
        principal_parameter=str(raw.get("principal_parameter", "user")),
        guard_functions=frozenset(raw.get("guard_functions", ["authorize"])),
        resource_loader_identity_args={
            str(key): int(value)
            for key, value in raw.get("resource_loader_identity_args", {}).items()
        },
        resource_loader_scope_args={
            str(key): int(value)
            for key, value in raw.get("resource_loader_scope_args", {}).items()
        },
        resource_loader_unconstrained_scopes=frozenset(
            raw.get("resource_loader_unconstrained_scopes", [])
        ),
        sink_binding_relations=dict(raw.get("sink_binding_relations", {})),
        sink_authorized_projections=dict(raw.get("sink_authorized_projections", {})),
        sink_acted_projections=dict(raw.get("sink_acted_projections", {})),
    )


def _evaluate(source: str, profile: ProtectedEffectProfile):
    materials = materials_from_pair(
        path="app.py",
        base_source=source,
        head_source=source,
        repo="benchmark/praisonai-reduced",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiProtectedEffectExtractor().compile(materials, profile)
    assert ir.coverage.status == "complete"
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return results[0]


def test_public_praisonai_reduction_distinguishes_unscoped_and_scoped_lookup() -> None:
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    profile = _profile(case["profile"])
    variants = {item["id"]: item for item in case["variants"]}

    vulnerable = _evaluate(
        variants["vulnerable_global_lookup"]["source"],
        profile,
    )
    secure = _evaluate(
        variants["secure_workspace_scoped_lookup"]["source"],
        profile,
    )

    assert secure.status == "pass"
    secure_resource = next(
        check for check in secure.checks if check.dimension == "resource_binding"
    )
    assert secure_resource.status == "established"

    if importlib.util.find_spec("z3") is None:
        assert vulnerable.status == "unknown"
        assert vulnerable.resource_binding_evidence[0].status == "unknown"
    else:
        assert vulnerable.status == "fail"
        assert vulnerable.resource_binding_evidence[0].status == "fail"
        counterexample = vulnerable.resource_binding_evidence[0].counterexample
        assert counterexample is not None
        assert counterexample["relation"] == "same_tenant"
