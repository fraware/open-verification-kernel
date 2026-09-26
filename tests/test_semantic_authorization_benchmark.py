from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from ovk.adapters.z3.resource_binding import evaluate_resource_binding_with_z3
from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi import (
    FastApiProtectedEffectExtractor,
    ProtectedEffectProfile,
)


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


def _evaluate(source: str, profile: ProtectedEffectProfile) -> tuple[object, dict]:
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
    assert len(ir.resource_bindings) == 1
    binding = ir.resource_bindings[0]
    return binding, evaluate_resource_binding_with_z3(ir, binding)


def test_public_praisonai_reduction_distinguishes_unscoped_and_scoped_lookup() -> None:
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    profile = _profile(case["profile"])
    variants = {item["id"]: item for item in case["variants"]}

    vulnerable_binding, vulnerable = _evaluate(
        variants["vulnerable_global_lookup"]["source"],
        profile,
    )
    secure_binding, secure = _evaluate(
        variants["secure_workspace_scoped_lookup"]["source"],
        profile,
    )

    assert vulnerable_binding.relation == "same_tenant"
    assert vulnerable_binding.authorized_projection == "identity"
    assert vulnerable_binding.acted_projection == "scope"
    assert secure_binding.relation == "same_tenant"

    if importlib.util.find_spec("z3") is None:
        assert vulnerable["status"] == "unknown"
        assert vulnerable["reason"] == "z3-solver is not installed"
    else:
        assert vulnerable["status"] == "fail"
        assert vulnerable["counterexample"]["relation"] == "same_tenant"

    assert secure["status"] == "pass"
