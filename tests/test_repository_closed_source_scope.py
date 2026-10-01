"""Repository-closed source scope for trusted bypass (#146).

Closed-world proofs must come from the complete authenticated Python
manifest, not PE ``source_paths``-filtered materials. Durable evidence
retains the full derived scope digest.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority_unit
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.repository_scope_proof import (
    derive_closed_world_scope_proof,
    derive_python_source_roots,
)
from ovk.compilers.authorization.trusted_bypass_authorization import (
    closed_world_scope_digest,
)
from ovk.core.bundle import content_digest


_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"sink": "model.invoke"},
    sink_static_resources={"sink": "chat"},
    trusted_bypass_authorities={
        "request.state.bypass_filter": ("model.invoke",),
    },
    principal_parameter="user",
)


def _routes_with_literal_writer() -> dict[str, str]:
    return {
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

def attach(request):
    request.state.bypass_filter = True

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip(),
    }


def test_derive_python_source_roots_prefers_backend() -> None:
    roots = derive_python_source_roots(
        [
            "backend/open_webui/routers/openai.py",
            "backend/open_webui/utils/auth.py",
        ]
    )
    assert roots == ("backend",)


def test_derive_python_source_roots_prefers_src() -> None:
    assert derive_python_source_roots(["src/pkg/mod.py"]) == ("src",)


def test_derive_python_source_roots_falls_back_to_repo_root() -> None:
    assert derive_python_source_roots(["app/routes.py"]) == (".",)


def test_derive_python_source_roots_keeps_outside_paths_with_dot() -> None:
    roots = derive_python_source_roots(
        [
            "backend/pkg/a.py",
            "scripts/tool.py",
        ]
    )
    assert roots == (".", "backend")


def test_filtered_head_files_without_manifest_do_not_authorize() -> None:
    """source_paths-filtered materials alone must not claim repo closure."""

    files = _routes_with_literal_writer()
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/app",
        base_revision="base",
        head_revision="head",
        repository_python_files=None,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, _PROFILE)
    assert ir.bypass_authority_evidence
    assert all(item.status != "established" for item in ir.bypass_authority_evidence)


def test_omitted_client_writer_outside_source_paths_must_not_authorize() -> None:
    """Writer omitted from source_paths must block authorization under full closure.

    The PE view alone looks like a proved literal writer. The omitted module
    introduces an unresolved/client-shaped write. Without the full authenticated
    Python manifest, product compile must refuse established status; with the
    manifest, authorization must also be refused.
    """

    pe_files = {
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

def attach(request):
    request.state.bypass_filter = True

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip(),
    }
    omitted_writer = {
        "middleware/external.py": """
def attach_external(request, bypass_filter):
    request.state.bypass_filter = bypass_filter
""".strip(),
    }
    full = {**pe_files, **omitted_writer}

    # Bug class: PE view alone with repo identity must not authorize.
    filtered = AuthMaterials(
        base_files=pe_files,
        head_files=pe_files,
        repo="example/app",
        base_revision="base",
        head_revision="head",
        repository_python_files=None,
    )
    filtered_ir = FastApiDependencyEffectExtractor().compile(filtered, _PROFILE)
    assert all(
        item.status != "established" for item in filtered_ir.bypass_authority_evidence
    )

    # Full authenticated manifest accounts for the omitted writer and refuses
    # established (Unknown > false PASS). Literal-only PE materials would have
    # falsely authorized under the old source_paths-as-closure bug.
    closed = AuthMaterials(
        base_files=pe_files,
        head_files=pe_files,
        repo="example/app",
        base_revision="base",
        head_revision="head",
        repository_python_files=full,
    )
    closed_ir = FastApiDependencyEffectExtractor().compile(closed, _PROFILE)
    assert closed_ir.bypass_authority_evidence
    assert all(
        item.status != "established" for item in closed_ir.bypass_authority_evidence
    )

    # Control: the PE subset alone, incorrectly treated as complete closure,
    # would authorize — proving the omitted writer is what blocks PASS.
    subset_only = AuthMaterials(
        base_files=pe_files,
        head_files=pe_files,
        repo="example/app",
        base_revision="base",
        head_revision="head",
        repository_python_files=pe_files,
    )
    subset_ir = FastApiDependencyEffectExtractor().compile(subset_only, _PROFILE)
    assert any(
        item.status == "established" for item in subset_ir.bypass_authority_evidence
    )


def test_complete_manifest_literal_writer_establishes_and_keeps_derived_digest() -> None:
    files = _routes_with_literal_writer()
    derived = derive_closed_world_scope_proof(
        repo="example/app",
        revision="head",
        files=files,
        source_roots=derive_python_source_roots(files),
        field_searched="bypass_filter",
        import_resolution_status="authenticated_revision_python_manifest_v2",
    )
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/app",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, _PROFILE)
    established = [
        item for item in ir.bypass_authority_evidence if item.status == "established"
    ]
    assert established
    for item in established:
        assert item.closed_world_scope_digest == derived.digest()
        # Must not collapse to the stripped path/root digest.
        stripped = closed_world_scope_digest(derived.as_closed_world_scope_proof())
        assert item.closed_world_scope_digest != stripped
        assert item.closed_world_scope_digest == content_digest(
            {
                "repo": derived.repo,
                "revision": derived.revision,
                "source_roots": list(derived.source_roots),
                "accounted_paths": list(derived.accounted_paths),
                "file_manifest_digest": derived.file_manifest_digest,
                "analyzed_paths": list(derived.analyzed_paths),
                "field_searched": derived.field_searched,
                "unsupported_dynamics": list(derived.unsupported_dynamics),
                "import_resolution_status": derived.import_resolution_status,
                "implementation_version": derived.implementation_version,
            }
        )


def test_backend_open_webui_import_resolves_under_derived_roots() -> None:
    """Correct roots keep local packages inside the closed world.

    Sparse units that omit a local ``open_webui.*`` submodule while the
    package prefix is present must refuse authorized (Unknown > false PASS).
    Manifest-complete product compile supplies the full authenticated
    revision so genuine local modules resolve uniquely.
    """

    full = {
        "backend/open_webui/utils/auth.py": """
def attach(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
        "backend/open_webui/routers/openai.py": """
from open_webui.utils.auth import attach

def middleware(request):
    request.state.bypass_filter = True

def handler(request):
    if request.state.bypass_filter:
        return sink()
    return sink()
""".strip(),
    }
    roots = derive_python_source_roots(full)
    assert roots == ("backend",)
    proof = derive_closed_world_scope_proof(
        repo="open-webui/open-webui",
        revision="rev",
        files=full,
        source_roots=roots,
        field_searched="bypass_filter",
    )
    findings = analyze_bypass_authority_unit(
        full,
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=proof.as_closed_world_scope_proof(),
    )
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True
    assert findings[0].status != "authorized"

    # Sparse unit omits auth.py while open_webui/ still appears — local miss.
    sparse = {
        "backend/open_webui/routers/openai.py": full[
            "backend/open_webui/routers/openai.py"
        ],
    }
    for source_roots in ((".",), ("backend",)):
        sparse_proof = derive_closed_world_scope_proof(
            repo="open-webui/open-webui",
            revision="rev",
            files=sparse,
            source_roots=source_roots,
            field_searched="bypass_filter",
        )
        sparse_findings = analyze_bypass_authority_unit(
            sparse,
            entry_path="backend/open_webui/routers/openai.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=sparse_proof.as_closed_world_scope_proof(),
        )
        assert sparse_findings[0].closed_world is not None
        assert sparse_findings[0].closed_world.complete is False
        assert sparse_findings[0].status != "authorized"
        assert any(
            "unresolvable_local_import:open_webui.utils.auth" in item
            for item in sparse_findings[0].closed_world.unresolvable_imports
        )
