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
    "benchmarks/formal_pr_bench/semantic_authorization_v4/"
    "synthetic_project_document_parent_binding.json"
)


def _profile(raw: dict) -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects=dict(raw["sink_effects"]),
        sink_identity_args={
            str(key): int(value)
            for key, value in raw.get("sink_identity_args", {}).items()
        },
        sink_contracts=dict(raw.get("sink_contracts", {})),
        sink_binding_relations=dict(raw.get("sink_binding_relations", {})),
        sink_binding_authorized_projections=dict(
            raw.get("sink_binding_authorized_projections", {})
        ),
        sink_binding_acted_projections=dict(
            raw.get("sink_binding_acted_projections", {})
        ),
        sink_binding_acted_attributes=dict(
            raw.get("sink_binding_acted_attributes", {})
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
            "routes/documents.py": route_source,
            "services/document_service.py": service_source,
        },
        head_files={
            "routes/documents.py": route_source,
            "services/document_service.py": service_source,
        },
        repo="benchmark/project-documents",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return ir, results[0]


def test_parent_attribute_development_case() -> None:
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    profile = _profile(case["profile"])
    variants = {item["id"]: item for item in case["variants"]}

    secure_ir, secure = _evaluate(
        variants["secure_parent_binding"]["route_source"],
        case["service_source"],
        profile,
    )
    vulnerable_ir, vulnerable = _evaluate(
        variants["wrong_parent_argument"]["route_source"],
        case["service_source"],
        profile,
    )

    assert secure_ir.coverage.status == "complete"
    assert vulnerable_ir.coverage.status == "complete"
    assert secure.status == "pass"

    secure_resource = next(
        resource for resource in secure_ir.resources if resource.symbol == "document_id"
    )
    assert secure_resource.attribute_terms["project_id"].value == "project_id"

    vulnerable_resource = next(
        resource for resource in vulnerable_ir.resources if resource.symbol == "document_id"
    )
    assert vulnerable_resource.attribute_terms["project_id"].value == "other_project_id"

    if importlib.util.find_spec("z3") is None:
        assert vulnerable.status == "unknown"
    else:
        assert vulnerable.status == "fail"
        evidence = vulnerable.resource_binding_evidence[0]
        assert evidence.counterexample is not None
        assert evidence.counterexample["acted_attribute"] == "project_id"
