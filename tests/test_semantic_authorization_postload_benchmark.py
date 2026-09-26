from __future__ import annotations

import json
from pathlib import Path

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
    ResourceScopeAssertionSemantics,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity


CASE_PATH = Path(
    "benchmarks/formal_pr_bench/semantic_authorization_v4/"
    "praisonai_agent_get_postload_workspace_assertion.json"
)
PROVENANCE_PATH = Path(
    "benchmarks/formal_pr_bench/provenance/"
    "praisonai_agent_get_postload_workspace_assertion.json"
)


def _load_case() -> dict:
    return json.loads(CASE_PATH.read_text(encoding="utf-8"))


def _profile(payload: dict) -> FastApiDependencyEffectProfile:
    raw = payload["profile"]
    return FastApiDependencyEffectProfile(
        sink_effects=dict(raw["sink_effects"]),
        sink_identity_args={
            key: int(value)
            for key, value in raw["sink_identity_args"].items()
        },
        sink_missing_scope_unconstrained=frozenset(
            raw["sink_missing_scope_unconstrained"]
        ),
        scope_assertions={
            key: ResourceScopeAssertionSemantics(**spec)
            for key, spec in raw["scope_assertions"].items()
        },
        dependency_guard_resources=dict(
            raw["dependency_guard_resources"]
        ),
        dependency_guard_effects={
            key: tuple(value)
            for key, value in raw["dependency_guard_effects"].items()
        },
        principal_parameter=str(raw["principal_parameter"]),
    )


def _evaluate(source: str):
    payload = _load_case()
    materials = materials_from_pair(
        path="routes/agents.py",
        base_source=source,
        head_source=source,
        repo="MervinPraison/PraisonAI",
        base_revision="historical",
        head_revision="candidate",
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(payload),
    )
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return ir, results[0]


def _variant(case: dict, variant_id: str) -> dict:
    return next(
        variant
        for variant in case["variants"]
        if variant["id"] == variant_id
    )


def test_public_case_is_content_bound_to_upstream_route_versions() -> None:
    provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))

    assert provenance["case_id"] == _load_case()["case_id"]
    assert provenance["contamination_status"] == "public_development_case"
    assert provenance["eligible_for_sealed_holdout"] is False
    assert (
        provenance["upstream"]["vulnerable_revision"]
        == "402d7ed9fc5926babaa70c97a6ee5353e3d0dd62"
    )
    assert (
        provenance["upstream"]["fixed_revision"]
        == "179cab02dbec0c1e9b601507a65908e079876004"
    )
    assert (
        provenance["upstream"]["vulnerable_route_blob"]
        == "c833dc7fe69d2ba5d37ffed7f83b15e4ec77514b"
    )
    assert (
        provenance["upstream"]["fixed_route_blob"]
        == "10bfc244645b89191587740a54ba10ac579f2a00"
    )


def test_reduction_changes_only_the_upstream_scope_assertion() -> None:
    case = _load_case()
    vulnerable = _variant(case, "vulnerable")["source"]
    secure = _variant(case, "secure")["source"]
    assertion = (
        "    ensure_resource_in_workspace("
        "agent.workspace_id, workspace_id, label=\"Agent\")\n"
    )

    assert assertion in secure
    assert assertion not in vulnerable
    assert secure.replace(assertion, "") == vulnerable


def test_upstream_repaired_shape_passes_with_complete_coverage() -> None:
    case = _load_case()
    secure = _variant(case, "secure")["source"]

    ir, result = _evaluate(secure)

    assert ir.coverage.status == "complete"
    assert result.status == "pass"
    binding = ir.resource_bindings[0]
    assertion_line = next(
        index
        for index, line in enumerate(secure.splitlines(), start=1)
        if "ensure_resource_in_workspace(" in line
    )
    assert binding.origin.source_range is not None
    assert binding.origin.source_range.start_line == assertion_line


def test_historical_vulnerable_shape_never_passes() -> None:
    case = _load_case()
    vulnerable = _variant(case, "vulnerable")["source"]

    ir, result = _evaluate(vulnerable)

    assert ir.coverage.status == "complete"
    acted = next(
        resource for resource in ir.resources if resource.symbol == "agent"
    )
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}
    assert result.status != "pass"
