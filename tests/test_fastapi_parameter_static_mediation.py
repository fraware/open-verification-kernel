from __future__ import annotations

import pytest

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig


PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"storage.delete_by_tags": "documents.delete"},
    sink_static_resources={
        "storage.delete_by_tags": "documents_write_surface"
    },
    dependency_guard_static_resources={
        "require_write_access": "documents_write_surface"
    },
    dependency_guard_static_effects={
        "require_write_access": ("documents.delete",),
    },
    principal_parameter="user",
)


def _compile(
    source: str,
    profile: FastApiDependencyEffectProfile = PROFILE,
):
    materials = materials_from_pair(
        path="documents.py",
        base_source=source,
        head_source=source,
        repo="example/parameter-static-mediation",
        base_revision="base",
        head_revision="head",
    )
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def _evaluation(
    source: str,
    profile: FastApiDependencyEffectProfile = PROFILE,
):
    ir = _compile(source, profile)
    evaluations = evaluate_protected_effect_integrity(ir)
    assert len(evaluations) == 1
    return ir, evaluations[0]


def test_parameter_dependency_completely_mediates_static_effect() -> None:
    source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.delete("/remove-by-tags")
async def remove_documents_by_tags(
    tags: list[str],
    user = Depends(require_write_access),
):
    try:
        storage = get_storage()
        count, message, deleted_hashes = await storage.delete_by_tags(tags)
        for item in deleted_hashes:
            audit(item)
        return count
    except Exception:
        return 0
""".strip()

    ir, evaluation = _evaluation(source)

    assert ir.coverage.status == "partial"
    assert evaluation.extraction_coverage == "complete"
    assert evaluation.status == "pass"
    assert len(ir.guards) == 1
    assert ir.guards[0].resource_id == ir.protected_effects[0].resource_id


def test_missing_parameter_dependency_does_not_authorize_static_effect() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.delete("/remove-by-tags")
async def remove_documents_by_tags(tags: list[str]):
    storage = get_storage()
    return await storage.delete_by_tags(tags)
""".strip()

    ir, evaluation = _evaluation(source)

    assert ir.guards == []
    assert evaluation.extraction_coverage == "complete"
    assert evaluation.status == "fail"
    guard_check = next(
        check
        for check in evaluation.checks
        if check.dimension == "guard_presence"
    )
    assert guard_check.status == "violated"


def test_dependency_result_must_bind_configured_principal() -> None:
    source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.delete("/remove-by-tags")
async def remove_documents_by_tags(
    tags: list[str],
    auth = Depends(require_write_access),
):
    storage = get_storage()
    return await storage.delete_by_tags(tags)
""".strip()

    ir, evaluation = _evaluation(source)

    assert ir.guards == []
    assert evaluation.status != "pass"
    path = next(
        path
        for path in ir.paths
        if evaluation.protected_effect_id in path.protected_effect_ids
    )
    assert any(
        "static_dependency_principal_mismatch" in item
        for item in path.unsupported_constructs
    )


def test_dependency_factory_is_outside_static_parameter_subset() -> None:
    source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.delete("/remove-by-tags")
async def remove_documents_by_tags(
    tags: list[str],
    user = Depends(require_write_access()),
):
    storage = get_storage()
    return await storage.delete_by_tags(tags)
""".strip()

    ir, evaluation = _evaluation(source)

    assert ir.guards == []
    assert evaluation.status == "fail"


def test_static_parameter_guard_cannot_authorize_different_resource() -> None:
    profile = FastApiDependencyEffectProfile(
        sink_effects={"storage.delete_by_tags": "documents.delete"},
        sink_static_resources={
            "storage.delete_by_tags": "documents_write_surface"
        },
        dependency_guard_static_resources={
            "require_write_access": "admin_console"
        },
        dependency_guard_static_effects={
            "require_write_access": ("documents.delete",),
        },
        principal_parameter="user",
    )
    source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.delete("/remove-by-tags")
async def remove_documents_by_tags(
    tags: list[str],
    user = Depends(require_write_access),
):
    storage = get_storage()
    return await storage.delete_by_tags(tags)
""".strip()

    ir, evaluation = _evaluation(source, profile)

    assert len(ir.guards) == 1
    assert ir.guards[0].resource_id != ir.protected_effects[0].resource_id
    assert evaluation.status == "fail"


def test_profile_rejects_static_parameter_effect_without_resource() -> None:
    with pytest.raises(ValueError, match="identical keys"):
        ProtectedEffectProfileConfig(
            source_paths=["documents.py"],
            sink_effects={"storage.delete_by_tags": "documents.delete"},
            sink_static_resources={
                "storage.delete_by_tags": "documents_write_surface"
            },
            dependency_guard_static_resources={},
            dependency_guard_static_effects={
                "require_write_access": ["documents.delete"]
            },
        )


def test_profile_rejects_static_and_dynamic_semantics_for_same_dependency() -> None:
    with pytest.raises(ValueError, match="both dynamic and static"):
        ProtectedEffectProfileConfig(
            source_paths=["documents.py"],
            sink_effects={"storage.delete_by_tags": "documents.delete"},
            sink_static_resources={
                "storage.delete_by_tags": "documents_write_surface"
            },
            dependency_guard_resources={
                "require_write_access": "workspace_id"
            },
            dependency_guard_effects={
                "require_write_access": ["documents.delete"]
            },
            dependency_guard_static_resources={
                "require_write_access": "documents_write_surface"
            },
            dependency_guard_static_effects={
                "require_write_access": ["documents.delete"]
            },
        )


def test_profile_rejects_unmodeled_static_parameter_effect() -> None:
    with pytest.raises(ValueError, match="absent from sink_effects"):
        ProtectedEffectProfileConfig(
            source_paths=["documents.py"],
            sink_effects={"storage.delete_by_tags": "documents.delete"},
            sink_static_resources={
                "storage.delete_by_tags": "documents_write_surface"
            },
            dependency_guard_static_resources={
                "require_write_access": "documents_write_surface"
            },
            dependency_guard_static_effects={
                "require_write_access": ["different.effect"]
            },
        )
