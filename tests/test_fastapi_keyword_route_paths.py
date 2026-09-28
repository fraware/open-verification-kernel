from __future__ import annotations

import ast

from ovk.compilers.authorization.fastapi_route_summary import summarize_route_file
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)


def _summary(source: str):
    return summarize_route_file(
        path="routes.py",
        tree=ast.parse(source),
        source_digest="test-digest",
    )


def test_literal_keyword_path_is_recognized_as_route() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.get(path="/items/{item_id}")
def get_item(item_id: int):
    return load_item(item_id)
""".strip()

    summary = _summary(source)

    assert len(summary.handlers) == 1
    handler = summary.handlers[0]
    assert handler.method == "GET"
    assert handler.route_path == "/items/{item_id}"
    assert handler.router_symbol == "router"


def test_keyword_path_preserves_path_interpretation_into_assurance_ir() -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt

router = APIRouter()

@router.get(path="/backfills/{backfill_id}")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()
    materials = AuthMaterials(
        head_files={"routes.py": source},
        repo="example/keyword-path",
        head_revision="head",
    )
    profile = FastApiDependencyEffectProfile(
        sink_effects={"load_backfill": "backfill.read"},
        sink_identity_args={"load_backfill": 0},
    )

    ir = FastApiDependencyEffectExtractor().compile(materials, profile)

    resources = [
        resource
        for resource in ir.resources
        if resource.symbol == "backfill_id"
    ]
    assert len(resources) == 1
    term = resources[0].identity_term
    assert term is not None
    assert term.interpretation is not None
    assert term.interpretation.input_origin == "request.path.backfill_id"
    assert term.interpretation.output_type == "pydantic.NonNegativeInt"


def test_keyword_path_keeps_dependency_factory_boundary() -> None:
    source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.put(
    path="/backfills/{backfill_id}",
    dependencies=[Depends(requires_access_backfill(method="PUT"))],
)
def pause_backfill(backfill_id: int):
    return load_backfill(backfill_id)
""".strip()

    summary = _summary(source)

    assert len(summary.handlers) == 1
    dependencies = summary.handlers[0].route_dependencies
    assert len(dependencies) == 1
    assert dependencies[0].full_name == "requires_access_backfill"
    assert dependencies[0].factory_call == (
        "requires_access_backfill(method='PUT')"
    )


def test_positional_and_keyword_path_is_rejected_as_ambiguous() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/items/{item_id}", path="/other/{item_id}")
def get_item(item_id: int):
    return load_item(item_id)
""".strip()

    assert _summary(source).handlers == ()


def test_dynamic_keyword_path_remains_outside_static_route_subset() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()
ROUTE = "/items/{item_id}"

@router.get(path=ROUTE)
def get_item(item_id: int):
    return load_item(item_id)
""".strip()

    assert _summary(source).handlers == ()
