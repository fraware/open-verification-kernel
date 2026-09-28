from __future__ import annotations

from pathlib import Path

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.persistent_fastapi_state import (
    PersistentFastApiIncrementalStateCache,
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
)


SAFE_WRAPPER = """
from typing import Any

from fastapi import APIRouter

class WrappedRouter(APIRouter):
    def api_route(
        self,
        path: str,
        operation_id: str | None = None,
        **kwargs: Any,
    ):
        def decorator(func):
            self.add_api_route(
                path,
                func,
                operation_id=operation_id or func.__name__,
                **kwargs,
            )
            return func
        return decorator
""".strip()


UNSAFE_PATH_WRAPPER = """
from typing import Any

from fastapi import APIRouter

class WrappedRouter(APIRouter):
    def api_route(
        self,
        path: str,
        operation_id: str | None = None,
        **kwargs: Any,
    ):
        def decorator(func):
            self.add_api_route(
                "/fixed",
                func,
                operation_id=operation_id or func.__name__,
                **kwargs,
            )
            return func
        return decorator
""".strip()


UNSAFE_GET_OVERRIDE = """
from typing import Any

from fastapi import APIRouter

class WrappedRouter(APIRouter):
    def api_route(
        self,
        path: str,
        operation_id: str | None = None,
        **kwargs: Any,
    ):
        def decorator(func):
            self.add_api_route(
                path,
                func,
                operation_id=operation_id or func.__name__,
                **kwargs,
            )
            return func
        return decorator

    def get(self, path):
        return custom_registration(path)
""".strip()


DIRECT_SUBCLASS = """
from fastapi import APIRouter

class WrappedRouter(APIRouter):
    pass
""".strip()


ROUTE = """
from app.router import WrappedRouter
from pydantic import NonNegativeInt

router = WrappedRouter()

@router.get(path="/backfills/{backfill_id}")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"load_backfill": "backfill.read"},
        sink_identity_args={"load_backfill": 0},
    )


def _materials(
    wrapper: str,
    *,
    revision: str = "head",
    duplicate_wrapper_root: bool = False,
) -> AuthMaterials:
    files = {
        "src/app/router.py": wrapper,
        "src/app/routes.py": ROUTE,
    }
    if duplicate_wrapper_root:
        files["vendor/app/router.py"] = wrapper
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/router-wrapper",
        base_revision="base",
        head_revision=revision,
    )


def _identity_term(materials: AuthMaterials):
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
    )
    resources = [
        resource
        for resource in ir.resources
        if resource.symbol == "backfill_id"
    ]
    assert len(resources) == 1
    term = resources[0].identity_term
    assert term is not None
    return term


def test_source_proved_api_route_delegate_enables_path_interpretation() -> None:
    term = _identity_term(_materials(SAFE_WRAPPER))

    assert term.interpretation is not None
    assert term.interpretation.input_origin == "request.path.backfill_id"
    assert term.interpretation.decoder == "fastapi.path_parameter"
    assert term.interpretation.output_type == "pydantic.NonNegativeInt"


def test_direct_apirouter_subclass_enables_path_interpretation() -> None:
    term = _identity_term(_materials(DIRECT_SUBCLASS))

    assert term.interpretation is not None
    assert term.interpretation.input_origin == "request.path.backfill_id"


def test_changed_path_delegation_does_not_establish_wrapper_semantics() -> None:
    term = _identity_term(_materials(UNSAFE_PATH_WRAPPER))

    assert term.interpretation is None


def test_extra_http_method_override_is_outside_wrapper_theorem() -> None:
    term = _identity_term(_materials(UNSAFE_GET_OVERRIDE))

    assert term.interpretation is None


def test_missing_wrapper_source_keeps_route_owner_unproved() -> None:
    materials = AuthMaterials(
        base_files={"src/app/routes.py": ROUTE},
        head_files={"src/app/routes.py": ROUTE},
        repo="example/router-wrapper-missing",
        base_revision="base",
        head_revision="head",
    )

    term = _identity_term(materials)

    assert term.interpretation is None


def test_ambiguous_module_roots_do_not_establish_wrapper_semantics() -> None:
    term = _identity_term(
        _materials(
            SAFE_WRAPPER,
            duplicate_wrapper_root=True,
        )
    )

    assert term.interpretation is None


def test_wrapper_interpretation_survives_persistent_summary_cache(
    tmp_path: Path,
) -> None:
    materials = _materials(SAFE_WRAPPER)
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"

    first = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    second = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )

    assert first.semantic_summary_stats.parse_count == 2
    assert second.semantic_summary_stats.parse_count == 0
    assert second.semantic_summary_stats.hits == 2

    resources = [
        resource
        for resource in second.compilation.ir.resources
        if resource.symbol == "backfill_id"
    ]
    assert len(resources) == 1
    term = resources[0].identity_term
    assert term is not None
    assert term.interpretation is not None


def test_wrapper_change_rebinds_unchanged_route_and_drops_interpretation(
    tmp_path: Path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    profile = _profile()

    first_materials = _materials(
        SAFE_WRAPPER,
        revision="safe-wrapper",
    )
    first = compile_persistent_incremental_fastapi_assurance(
        first_materials,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    first_term = next(
        resource.identity_term
        for resource in first.compilation.ir.resources
        if resource.symbol == "backfill_id"
    )
    assert first_term is not None
    assert first_term.interpretation is not None

    second_materials = _materials(
        UNSAFE_PATH_WRAPPER,
        revision="unsafe-wrapper",
    )
    second = compile_persistent_incremental_fastapi_assurance(
        second_materials,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    full = FastApiDependencyEffectExtractor().compile(
        second_materials,
        profile,
    )

    assert second.compilation.ir.canonical_payload() == full.canonical_payload()
    assert second.previous_state_loaded is True
    assert second.semantic_summary_stats.parse_count == 1
    assert second.semantic_summary_stats.hits == 1
    assert second.compilation.stats.rebound_file_count == 1
    assert second.compilation.stats.reused_fragment_count == 0

    second_term = next(
        resource.identity_term
        for resource in second.compilation.ir.resources
        if resource.symbol == "backfill_id"
    )
    assert second_term is not None
    assert second_term.interpretation is None
