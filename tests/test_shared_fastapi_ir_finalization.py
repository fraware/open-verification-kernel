"""Shared full/incremental FastAPI IR finalization (#157)."""

from __future__ import annotations

from ovk.compilers.authorization.incremental_fastapi_compiler import (
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import parse_head_python_materials
from ovk.compilers.authorization.fastapi_route_summary import build_route_summary_index
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
)


_TRUSTED_WRITER = """
def attach_trusted(request):
    request.state.bypass_filter = True
""".strip()

_CLIENT_WRITER = """
def attach_trusted(request):
    request.state.bypass_filter = True

def attach_client(state, bypass_filter):
    state.bypass_filter = bypass_filter
""".strip()

_ROUTES = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    attach_trusted(request)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()

_ROUTES_WITH_CLIENT = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    attach_trusted(request)
    attach_client(request.state, bypass_filter)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )


def _materials(
    *,
    writer_body: str,
    routes: str = _ROUTES,
    revision: str,
    pe_files: dict[str, str] | None = None,
    repository_files: dict[str, str] | None = None,
) -> AuthMaterials:
    full_repo = {
        "app/middleware.py": writer_body + "\n",
        "app/routes.py": routes,
    }
    if repository_files is not None:
        full_repo = dict(repository_files)
    pe_view = pe_files if pe_files is not None else {"app/routes.py": full_repo["app/routes.py"]}
    return AuthMaterials(
        base_files=dict(pe_view),
        head_files=pe_view,
        repo="example/finalize-bypass",
        base_revision="base",
        head_revision=revision,
        repository_python_files=full_repo,
        head_repository_python_files=full_repo,
        base_repository_python_files=full_repo,
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


def test_full_equals_initial_incremental_under_trusted_bypass() -> None:
    profile = _profile()
    materials = _materials(writer_body=_TRUSTED_WRITER, revision="head-1")
    # PE view includes middleware so attach_trusted resolves in-unit.
    materials = _materials(
        writer_body=_TRUSTED_WRITER,
        revision="head-1",
        pe_files={
            "app/middleware.py": _TRUSTED_WRITER + "\n",
            "app/routes.py": _ROUTES,
        },
    )
    full = _full(materials, profile)
    incremental = _incremental(materials, profile)
    assert full.canonical_payload() == incremental.ir.canonical_payload()
    assert full.bypass_authority_evidence
    assert incremental.state.head_repository_python_manifest_digest is not None
    assert incremental.state.derived_closed_world_scope_digest is not None


def test_full_equals_reused_incremental_under_trusted_bypass() -> None:
    profile = _profile()
    materials = _materials(
        writer_body=_TRUSTED_WRITER,
        revision="head-1",
        pe_files={
            "app/middleware.py": _TRUSTED_WRITER + "\n",
            "app/routes.py": _ROUTES,
        },
    )
    first = _incremental(materials, profile)
    second = _incremental(materials, profile, previous_state=first.state)
    full = _full(materials, profile)
    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.reused_fragment_count >= 1
    assert (
        second.state.head_repository_python_manifest_digest
        == first.state.head_repository_python_manifest_digest
    )


def test_writer_change_full_equals_rebound_incremental() -> None:
    profile = _profile()
    first_materials = _materials(
        writer_body=_TRUSTED_WRITER,
        revision="head-1",
        pe_files={
            "app/middleware.py": _TRUSTED_WRITER + "\n",
            "app/routes.py": _ROUTES,
        },
    )
    first = _incremental(first_materials, profile)
    second_materials = _materials(
        writer_body=_CLIENT_WRITER,
        routes=_ROUTES_WITH_CLIENT,
        revision="head-2",
        pe_files={
            "app/middleware.py": _CLIENT_WRITER + "\n",
            "app/routes.py": _ROUTES_WITH_CLIENT,
        },
    )
    second = _incremental(
        second_materials,
        profile,
        previous_state=first.state,
    )
    full = _full(second_materials, profile)
    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.rebound_file_count >= 1
    assert all(
        item.status != "established" for item in second.ir.bypass_authority_evidence
    )


def test_repository_manifest_only_writer_change_full_eq_incremental() -> None:
    """Out-of-profile writer change must still finalize identically.

    Route fragments may all reuse while closed-world bypass evidence changes.
    """

    profile = _profile()
    routes_only = {"app/routes.py": _ROUTES}
    trusted_repo = {
        "app/routes.py": _ROUTES,
        "app/middleware.py": _TRUSTED_WRITER + "\n",
    }
    client_repo = {
        "app/routes.py": _ROUTES,
        "app/middleware.py": """
def attach_trusted(request):
    request.state.bypass_filter = True

def sneaky(state, bypass_filter):
    state.bypass_filter = bypass_filter
""".strip()
        + "\n",
        "app/other.py": """
def poison(request, bypass_filter):
    request.state.bypass_filter = bypass_filter
""".strip()
        + "\n",
    }

    first_materials = AuthMaterials(
        base_files=dict(routes_only),
        head_files=dict(routes_only),
        repo="example/finalize-bypass",
        base_revision="base",
        head_revision="head-1",
        repository_python_files=trusted_repo,
        head_repository_python_files=trusted_repo,
        base_repository_python_files=trusted_repo,
    )
    first = _incremental(first_materials, profile)
    first_manifest = first.state.head_repository_python_manifest_digest
    first_scope = first.state.derived_closed_world_scope_digest

    second_materials = AuthMaterials(
        base_files=dict(routes_only),
        head_files=dict(routes_only),
        repo="example/finalize-bypass",
        base_revision="base",
        head_revision="head-2",
        repository_python_files=client_repo,
        head_repository_python_files=client_repo,
        base_repository_python_files=trusted_repo,
    )
    second = _incremental(
        second_materials,
        profile,
        previous_state=first.state,
    )
    full = _full(second_materials, profile)

    assert second.ir.canonical_payload() == full.canonical_payload()
    # Route PE files unchanged → fragments reusable; closure digest must move.
    assert second.stats.reused_fragment_count >= 1
    assert second.stats.rebound_file_count == 0
    assert second.state.head_repository_python_manifest_digest != first_manifest
    assert second.state.derived_closed_world_scope_digest != first_scope
    assert all(
        item.status != "established" for item in second.ir.bypass_authority_evidence
    )
