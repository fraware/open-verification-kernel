from __future__ import annotations

import ast
from pathlib import Path

from ovk.compilers.authorization.fastapi_route_summary import (
    RouteHandlerSummary,
    summarize_route_file,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
    load_persistent_semantic_summaries,
)


def _handler(source: str) -> RouteHandlerSummary:
    summary = summarize_route_file(
        path="routes.py",
        tree=ast.parse(source),
        source_digest="test-digest",
    )
    assert len(summary.handlers) == 1
    return summary.handlers[0]


def _first_call_term(source: str):
    handler = _handler(source)
    assert len(handler.calls) == 1
    assert len(handler.calls[0].positional_arguments) == 1
    return handler.calls[0].positional_arguments[0].term


def test_nonnegativeint_path_parameter_carries_interpretation_provenance() -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt

router = APIRouter()

@router.get("/backfills/{backfill_id}")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()

    term = _first_call_term(source)

    assert term is not None
    assert term.kind == "symbol"
    assert term.value == "backfill_id"
    assert term.interpretation is not None
    assert term.interpretation.input_origin == "request.path.backfill_id"
    assert term.interpretation.decoder == "fastapi.path_parameter"
    assert term.interpretation.output_type == "pydantic.NonNegativeInt"
    assert term.interpretation.constraints == (
        "ge=0",
        "validation_mode=default",
    )


def test_nonnegativeint_query_parameter_is_not_claimed_as_path_interpretation() -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt

router = APIRouter()

@router.get("/backfills")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()

    term = _first_call_term(source)

    assert term is not None
    assert term.value == "backfill_id"
    assert term.interpretation is None


def test_aliased_nonnegativeint_import_remains_outside_bounded_subset() -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt as NNInt

router = APIRouter()

@router.get("/backfills/{backfill_id}")
def get_backfill(backfill_id: NNInt):
    return load_backfill(backfill_id)
""".strip()

    term = _first_call_term(source)

    assert term is not None
    assert term.interpretation is None


def test_rebound_nonnegativeint_name_cannot_mint_interpretation_evidence() -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt

NonNegativeInt = int
router = APIRouter()

@router.get("/backfills/{backfill_id}")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()

    term = _first_call_term(source)

    assert term is not None
    assert term.interpretation is None


def test_annotated_path_customization_remains_outside_bounded_subset() -> None:
    source = """
from typing import Annotated

from fastapi import APIRouter, Path
from pydantic import NonNegativeInt

router = APIRouter()

@router.get("/backfills/{backfill_id}")
def get_backfill(
    backfill_id: Annotated[NonNegativeInt, Path(strict=True)],
):
    return load_backfill(backfill_id)
""".strip()

    term = _first_call_term(source)

    assert term is not None
    assert term.interpretation is None


def test_path_converter_syntax_remains_outside_bounded_subset() -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt

router = APIRouter()

@router.get("/backfills/{backfill_id:path}")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()

    term = _first_call_term(source)

    assert term is not None
    assert term.interpretation is None


def test_interpretation_survives_persistent_semantic_summary_cache(
    tmp_path: Path,
) -> None:
    source = """
from fastapi import APIRouter
from pydantic import NonNegativeInt

router = APIRouter()

@router.get("/backfills/{backfill_id}")
def get_backfill(backfill_id: NonNegativeInt):
    return load_backfill(backfill_id)
""".strip()
    materials = AuthMaterials(
        head_files={"routes.py": source},
        repo="example/interpreted-path",
        head_revision="head",
    )
    root = tmp_path / "semantic-summaries"

    first = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )
    second = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )

    assert first.stats.misses == 1
    assert second.stats.hits == 1
    assert second.stats.parse_count == 0

    handler = second.route_summary_index.summaries["routes.py"].handlers[0]
    term = handler.calls[0].positional_arguments[0].term
    assert term is not None
    assert term.interpretation is not None
    assert term.interpretation.input_origin == "request.path.backfill_id"
    assert term.interpretation.output_type == "pydantic.NonNegativeInt"
