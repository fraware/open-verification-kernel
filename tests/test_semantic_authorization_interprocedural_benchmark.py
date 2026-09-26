from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity


CASE_PATH = Path(
    "benchmarks/formal_pr_bench/semantic_authorization_v3/"
    "praisonai_cross_workspace_interprocedural_reduced.json"
)


def _profile(raw: dict) -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects=dict(raw["sink_effects"]),
        sink_identity_args={
            str(key): int(value)
            for key, value in raw.get("sink_identity_args", {}).items()
        },
        sink_contracts=dict(raw.get("sink_contracts", {})),
        dependency_guard_resources=dict(raw.get("dependency_guard_resources", {})),
        dependency_guard_effects={
            str(key): tuple(str(item) for item in value)
            for key, value in raw.get("dependency_guard_effects", {}).items()
        },
        principal_parameter=str(raw.get("principal_parameter", "user")),
    )


def _evaluate(route_source: str, service_source: str, profile: FastApiDependencyEffectProfile):
    materials = AuthMaterials(
        base_files={
            "praisonai_platform/api/routes/agents.py": route_source,
            "praisonai_platform/services/agent_service.py": service_source,
        },
        head_files={
            "praisonai_platform/api/routes/agents.py": route_source,
            "praisonai_platform/services/agent_service.py": service_source,
        },
        repo="benchmark/praisonai-platform-reduced",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return ir, results[0]


def test_public_interprocedural_reduction_detects_scope_regression() -> None:
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    profile = _profile(case["profile"])
    variants = {item["id"]: item for item in case["variants"]}
    service_source = case["service_source"]

    vulnerable_ir, vulnerable = _evaluate(
        variants["vulnerable_route_omits_scope"]["route_source"],
        service_source,
        profile,
    )
    secure_ir, secure = _evaluate(
        variants["secure_route_passes_scope"]["route_source"],
        service_source,
        profile,
    )

    assert vulnerable_ir.coverage.status == "complete"
    assert secure_ir.coverage.status == "complete"
    assert len(secure_ir.resource_return_contracts) == 1
    assert secure_ir.resource_return_contracts[0].qualified_name == "AgentService.get"
    assert secure.status == "pass"

    secure_acted = next(
        resource for resource in secure_ir.resources if resource.symbol == "agent_id"
    )
    assert secure_acted.scope_term is not None
    assert secure_acted.scope_term.value == "workspace_id"

    vulnerable_acted = next(
        resource for resource in vulnerable_ir.resources if resource.symbol == "agent_id"
    )
    assert vulnerable_acted.scope_term is not None
    assert vulnerable_acted.scope_term.value.startswith("$scope:")

    if importlib.util.find_spec("z3") is None:
        assert vulnerable.status == "unknown"
        assert vulnerable.resource_binding_evidence[0].status == "unknown"
    else:
        assert vulnerable.status == "fail"
        evidence = vulnerable.resource_binding_evidence[0]
        assert evidence.status == "fail"
        assert evidence.counterexample is not None
        assert evidence.counterexample["relation"] == "same_tenant"
