from pathlib import Path

import pytest

from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from tests.native_ci import skip_unless_z3


def _provenance_backend(evidence) -> str | None:
    for artifact in evidence.generated_artifacts:
        if artifact.get("kind") == "backend_provenance":
            return str(artifact.get("backend"))
    return None


@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_native_path_blocks_admin_bypass_when_z3_installed() -> None:
    payload = Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8")
    import json

    data = json.loads(payload)
    evidence = evaluate_validated_authorization_path(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision.get("merge_recommendation") == "block"
    assert _provenance_backend(evidence) == "z3"


@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_native_path_allows_protected_admin_route_when_z3_installed() -> None:
    payload = Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8")
    import json

    data = json.loads(payload)
    evidence = evaluate_validated_authorization_path(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision.get("merge_recommendation") == "allow"
    assert _provenance_backend(evidence) == "z3"



@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_refutes_wrong_interprocedural_parent_binding() -> None:
    import json

    from ovk.compilers.authorization.material_loader import AuthMaterials
    from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
        FastApiDependencyEffectExtractor,
        FastApiDependencyEffectProfile,
    )
    from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity

    case_path = Path(
        "benchmarks/formal_pr_bench/semantic_authorization_v4/"
        "synthetic_project_document_parent_binding.json"
    )
    case = json.loads(case_path.read_text(encoding="utf-8"))
    raw = case["profile"]
    profile = FastApiDependencyEffectProfile(
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
        sink_binding_acted_attributes=dict(raw.get("sink_binding_acted_attributes", {})),
        dependency_guard_resources=dict(raw.get("dependency_guard_resources", {})),
        dependency_guard_effects={
            str(key): tuple(str(item) for item in value)
            for key, value in raw.get("dependency_guard_effects", {}).items()
        },
        principal_parameter=str(raw.get("principal_parameter", "user")),
    )
    variants = {item["id"]: item for item in case["variants"]}

    def evaluate(route_source: str):
        materials = AuthMaterials(
            base_files={
                "routes/documents.py": route_source,
                "services/document_service.py": case["service_source"],
            },
            head_files={
                "routes/documents.py": route_source,
                "services/document_service.py": case["service_source"],
            },
            repo="benchmark/project-documents",
            base_revision="base",
            head_revision="head",
        )
        ir = FastApiDependencyEffectExtractor().compile(materials, profile)
        assert ir.coverage.status == "complete"
        results = evaluate_protected_effect_integrity(ir)
        assert len(results) == 1
        return results[0]

    secure = evaluate(variants["secure_parent_binding"]["route_source"])
    vulnerable = evaluate(variants["wrong_parent_argument"]["route_source"])

    assert secure.status == "pass"
    assert vulnerable.status == "fail"
    evidence = vulnerable.resource_binding_evidence[0]
    assert evidence.status == "fail"
    assert evidence.counterexample is not None
    assert evidence.counterexample["acted_projection"] == "attribute"
    assert evidence.counterexample["acted_attribute"] == "project_id"
