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
    "benchmarks/formal_pr_bench/semantic_authorization_v5/"
    "synthetic_composed_workspace_scope.json"
)


def _profile(raw: dict) -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects=dict(raw["sink_effects"]),
        sink_identity_args={
            str(key): int(value)
            for key, value in raw.get("sink_identity_args", {}).items()
        },
        sink_contracts=dict(raw.get("sink_contracts", {})),
        sink_contract_scope_attributes=dict(
            raw.get("sink_contract_scope_attributes", {})
        ),
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
            "routes/agents.py": route_source,
            "services/agent_service.py": service_source,
        },
        head_files={
            "routes/agents.py": route_source,
            "services/agent_service.py": service_source,
        },
        repo="benchmark/composed-workspace",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return ir, results[0]


def test_composed_workspace_scope_development_case() -> None:
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    profile = _profile(case["profile"])
    variants = {item["id"]: item for item in case["variants"]}

    secure_ir, secure = _evaluate(
        variants["secure_composed_scope"]["route_source"],
        case["service_source"],
        profile,
    )
    vulnerable_ir, vulnerable = _evaluate(
        variants["missing_scope_at_route"]["route_source"],
        case["service_source"],
        profile,
    )

    by_name = {contract.qualified_name for contract in secure_ir.function_contracts}
    assert {"AgentRepository.get", "AgentService.get"} <= by_name
    assert secure_ir.coverage.status == "complete"
    assert vulnerable_ir.coverage.status == "complete"
    assert secure.status == "pass"

    if importlib.util.find_spec("z3") is None:
        assert vulnerable.status == "unknown"
    else:
        assert vulnerable.status == "fail"
        assert vulnerable.resource_binding_evidence[0].counterexample is not None
