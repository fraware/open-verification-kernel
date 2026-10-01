"""Manifest import closure + dual base/head Python manifests (#155)."""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    _module_candidates_in_manifest,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.python_import_space import (
    module_candidates_in_manifest,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig


def test_module_candidates_exact_one_multiple_none() -> None:
    available = {
        "python/acme/auth.py",
        "python/acme/routes.py",
        "src/acme/auth.py",
        "lib/other.py",
        "acme/auth.py",
    }
    # Without import roots, only exact repo-root paths bind.
    assert module_candidates_in_manifest("acme.auth", available) == ("acme/auth.py",)
    assert module_candidates_in_manifest("acme.routes", available) == ()
    assert module_candidates_in_manifest("missing.mod", available) == ()
    # Trusted roots contribute; multiple roots may be ambiguous.
    assert module_candidates_in_manifest(
        "acme.auth", available, import_roots=("python", "src")
    ) == (
        "acme/auth.py",
        "python/acme/auth.py",
        "src/acme/auth.py",
    )
    assert _module_candidates_in_manifest(
        "acme.routes", available, import_roots=("python",)
    ) == ("python/acme/routes.py",)


def test_auth_materials_carries_base_and_head_closure() -> None:
    materials = AuthMaterials(
        base_files={"app/a.py": "x=1\n"},
        head_files={"app/a.py": "x=2\n"},
        base_repository_python_files={"app/a.py": "x=1\n", "app/b.py": "y=1\n"},
        head_repository_python_files={"app/a.py": "x=2\n", "app/b.py": "y=2\n"},
        repository_python_files={"app/a.py": "x=2\n", "app/b.py": "y=2\n"},
    )
    assert materials.closure_files_for_revision(head=True) == (
        materials.head_repository_python_files
    )
    assert materials.closure_files_for_revision(head=False) == (
        materials.base_repository_python_files
    )
    # Legacy alias tracks head.
    assert materials.repository_python_files == materials.head_repository_python_files


def test_profile_has_distinct_closure_budgets() -> None:
    payload = {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["app/**/*.py"],
        "sink_effects": {"sink": "model.invoke"},
        "max_files": 10,
        "max_total_bytes": 4096,
        "closure_max_files": 1000,
        "closure_max_total_bytes": 1_000_000,
    }
    config = ProtectedEffectProfileConfig.model_validate(payload)
    assert config.max_files == 10
    assert config.closure_max_files == 1000
    assert config.closure_max_total_bytes == 1_000_000


def test_init_module_candidate_resolves() -> None:
    files = {
        "server/acme/auth/__init__.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "server/acme/routes.py": """
from acme.auth import attach

def handler(request):
    return request.state.bypass_filter
""".strip(),
    }
    findings = analyze_bypass_authority_unit(
        files,
        entry_path="server/acme/routes.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=ClosedWorldScopeProof(
            accounted_paths=tuple(files),
            source_roots=(".",),
            python_import_roots=("server",),
        ),
    )
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True
    assert findings[0].status == "authorized"
