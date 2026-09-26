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
def test_z3_proves_interprocedural_workspace_scope_regression() -> None:
    import json

    from ovk.compilers.authorization.material_loader import AuthMaterials
    from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
        FastApiDependencyEffectExtractor,
        FastApiDependencyEffectProfile,
    )
    from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity

    case_path = Path(
        "benchmarks/formal_pr_bench/semantic_authorization_v3/"
        "praisonai_cross_workspace_interprocedural_reduced.json"
    )
    case = json.loads(case_path.read_text(encoding="utf-8"))
    raw_profile = case["profile"]
    profile = FastApiDependencyEffectProfile(
        sink_effects=dict(raw_profile["sink_effects"]),
        sink_identity_args={
            str(key): int(value)
            for key, value in raw_profile.get("sink_identity_args", {}).items()
        },
        sink_contracts=dict(raw_profile.get("sink_contracts", {})),
        dependency_guard_resources=dict(
            raw_profile.get("dependency_guard_resources", {})
        ),
        dependency_guard_effects={
            str(key): tuple(str(item) for item in value)
            for key, value in raw_profile.get("dependency_guard_effects", {}).items()
        },
        principal_parameter=str(raw_profile.get("principal_parameter", "user")),
    )
    variants = {item["id"]: item for item in case["variants"]}

    def evaluate(route_source: str):
        materials = AuthMaterials(
            base_files={
                "praisonai_platform/api/routes/agents.py": route_source,
                "praisonai_platform/services/agent_service.py": case["service_source"],
            },
            head_files={
                "praisonai_platform/api/routes/agents.py": route_source,
                "praisonai_platform/services/agent_service.py": case["service_source"],
            },
            repo="benchmark/praisonai-platform-reduced",
            base_revision="base",
            head_revision="head",
        )
        ir = FastApiDependencyEffectExtractor().compile(materials, profile)
        assert ir.coverage.status == "complete"
        results = evaluate_protected_effect_integrity(ir)
        assert len(results) == 1
        return results[0]

    secure = evaluate(variants["secure_route_passes_scope"]["route_source"])
    vulnerable = evaluate(variants["vulnerable_route_omits_scope"]["route_source"])

    assert secure.status == "pass"
    assert vulnerable.status == "fail"
    assert len(vulnerable.resource_binding_evidence) == 1
    binding_evidence = vulnerable.resource_binding_evidence[0]
    assert binding_evidence.status == "fail"
    assert binding_evidence.counterexample is not None
    assert binding_evidence.counterexample["relation"] == "same_tenant"
