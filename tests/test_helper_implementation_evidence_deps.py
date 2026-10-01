"""Helper implementation evidence + incremental dependency tracking (#152)."""

from __future__ import annotations

from ovk.compilers.authorization.body_helper_contracts import (
    analyze_body_helper_implementation,
)
from ovk.compilers.authorization.incremental_fastapi_compiler import (
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    BodyAuthorizationHelperSemantics,
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import parse_head_python_materials
from ovk.compilers.authorization.fastapi_route_summary import build_route_summary_index
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
)


_HELPER_RAISE = """
def require_access(user):
    if user is None:
        raise HTTPException(status_code=403)
""".strip()

_HELPER_NOOP = """
def require_access(user):
    return True
""".strip()

_ROUTES = """
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip()


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        body_authorization_helpers={
            "require_access": BodyAuthorizationHelperSemantics(
                authorized_effects=("model.invoke",),
                principal_arg=0,
                authorized_resource="chat",
            )
        },
        principal_parameter="user",
    )


def _materials(helper_body: str, *, revision: str) -> AuthMaterials:
    files = {
        "app/helpers.py": helper_body + "\n",
        "app/routes.py": _ROUTES,
    }
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/helper-deps",
        base_revision="base",
        head_revision=revision,
        repository_python_files=files,
    )


def _indexes(materials: AuthMaterials):
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    return parsed, contracts, routes


def _incremental(materials, profile, previous_state=None):
    parsed, contracts, routes = _indexes(materials)
    return compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
        previous_state=previous_state,
    )


def _full(materials, profile):
    parsed, contracts, routes = _indexes(materials)
    return FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )


def test_helper_evidence_records_qualified_symbol_and_digests() -> None:
    files = {
        "app/helpers.py": _HELPER_RAISE + "\n",
        "app/routes.py": _ROUTES,
    }
    evidence = analyze_body_helper_implementation(
        files, helper_name="require_access"
    )
    assert evidence.status == "unproved"
    assert evidence.qualified_symbol.startswith("app/helpers.py:require_access@")
    assert evidence.source_digest
    assert evidence.implementation_digest
    assert evidence.evidence_id.startswith("bhe:")
    ir = _full(_materials(_HELPER_RAISE, revision="head"), _profile())
    assert ir.helper_effectiveness_evidence
    typed = ir.helper_effectiveness_evidence[0]
    assert typed.qualified_symbol == evidence.qualified_symbol
    assert typed.implementation_digest == evidence.implementation_digest
    assert typed.status == "unproved"
    assert ir.guards[0].effectiveness_evidence_ids == [typed.evidence_id]


def test_helper_impl_change_invalidates_route_fragment_full_eq_incremental() -> None:
    """routes.py unchanged; helpers.py body change must rebind and match full."""

    profile = _profile()
    first_materials = _materials(_HELPER_RAISE, revision="head-1")
    first = _incremental(first_materials, profile)
    first_digest = first.ir.helper_effectiveness_evidence[0].implementation_digest

    second_materials = _materials(_HELPER_NOOP, revision="head-2")
    second = _incremental(
        second_materials,
        profile,
        previous_state=first.state,
    )
    full = _full(second_materials, profile)

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.rebound_file_count >= 1
    # Route fragment depended on helper impl; must not stale-reuse raise digest.
    assert second.ir.helper_effectiveness_evidence
    second_digest = second.ir.helper_effectiveness_evidence[0].implementation_digest
    assert second_digest != first_digest
    assert second.ir.helper_effectiveness_evidence[0].reason == (
        "helper_implementation_noop"
    )


def test_unchanged_helper_allows_route_fragment_reuse() -> None:
    profile = _profile()
    first = _incremental(_materials(_HELPER_RAISE, revision="head-1"), profile)
    second = _incremental(
        _materials(_HELPER_RAISE, revision="head-2"),
        profile,
        previous_state=first.state,
    )
    full = _full(_materials(_HELPER_RAISE, revision="head-2"), profile)
    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.reused_fragment_count >= 1
    assert second.stats.rebound_file_count == 0
