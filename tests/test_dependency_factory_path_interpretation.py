from __future__ import annotations

import ast
from pathlib import Path

from ovk.compilers.authorization.fastapi_route_summary import summarize_route_file
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
    load_persistent_semantic_summaries,
)


FIXED_SOURCE = """
from fastapi import Request
from pydantic import NonNegativeInt, TypeAdapter, ValidationError

_BACKFILL_ID_ADAPTER: TypeAdapter[NonNegativeInt] = TypeAdapter(NonNegativeInt)


def requires_access_backfill(method):
    async def inner(request: Request):
        backfill_id_raw = request.path_params.get("backfill_id")
        try:
            backfill_id = (
                _BACKFILL_ID_ADAPTER.validate_python(backfill_id_raw)
                if backfill_id_raw is not None
                else None
            )
        except ValidationError:
            backfill_id = None
        authorize(method, backfill_id)

    return inner
""".strip()


VULNERABLE_SOURCE = """
from fastapi import Request


def requires_access_backfill(method):
    async def inner(request: Request):
        backfill_id_raw = request.path_params.get("backfill_id")
        try:
            backfill_id = (
                int(backfill_id_raw)
                if backfill_id_raw is not None
                else None
            )
        except ValueError:
            backfill_id = None
        authorize(method, backfill_id)

    return inner
""".strip()


def _interpretations(source: str):
    summary = summarize_route_file(
        path="security.py",
        tree=ast.parse(source),
        source_digest="sha256:test",
    )
    return summary.dependency_factory_interpretations


def test_type_adapter_nonnegativeint_interpretation_is_source_grounded() -> None:
    items = _interpretations(FIXED_SOURCE)

    assert len(items) == 1
    item = items[0]
    assert item.factory_name == "requires_access_backfill"
    assert item.returned_callable_name == "inner"
    assert item.request_parameter == "request"
    assert item.path_parameter == "backfill_id"
    assert item.raw_symbol == "backfill_id_raw"
    assert item.parsed_symbol == "backfill_id"

    interpretation = item.term.interpretation
    assert interpretation is not None
    assert interpretation.input_origin == "request.path.backfill_id"
    assert interpretation.decoder == "pydantic.TypeAdapter.validate_python"
    assert interpretation.output_type == "pydantic.NonNegativeInt"
    assert interpretation.constraints == (
        "ge=0",
        "validation_mode=default",
    )


def test_builtin_int_interpretation_is_distinct_on_same_raw_path() -> None:
    vulnerable = _interpretations(VULNERABLE_SOURCE)
    fixed = _interpretations(FIXED_SOURCE)

    assert len(vulnerable) == 1
    assert len(fixed) == 1
    vulnerable_term = vulnerable[0].term
    fixed_term = fixed[0].term
    assert vulnerable_term.interpretation is not None
    assert fixed_term.interpretation is not None
    assert (
        vulnerable_term.interpretation.input_origin
        == fixed_term.interpretation.input_origin
        == "request.path.backfill_id"
    )
    assert vulnerable_term.interpretation.decoder == "python.int"
    assert vulnerable_term.interpretation.output_type == "builtins.int"
    assert vulnerable_term != fixed_term


def test_type_adapter_binding_reassignment_suppresses_interpretation() -> None:
    source = FIXED_SOURCE.replace(
        "\n\ndef requires_access_backfill",
        "\n\nif FLAG:\n    _BACKFILL_ID_ADAPTER = custom_adapter\n\ndef requires_access_backfill",
    )

    assert _interpretations(source) == ()


def test_raw_path_alias_reassignment_suppresses_interpretation() -> None:
    source = FIXED_SOURCE.replace(
        '        try:\n',
        '        backfill_id_raw = normalize(backfill_id_raw)\n        try:\n',
    )

    assert _interpretations(source) == ()


def test_shadowed_int_does_not_mint_builtin_interpretation() -> None:
    source = VULNERABLE_SOURCE.replace(
        "from fastapi import Request\n",
        "from fastapi import Request\nint = custom_int\n",
    )

    assert _interpretations(source) == ()


def test_non_request_parameter_does_not_mint_path_interpretation() -> None:
    source = FIXED_SOURCE.replace(
        "async def inner(request: Request):",
        "async def inner(request):",
    )

    assert _interpretations(source) == ()


def test_factory_interpretation_survives_persistent_summary_cache(
    tmp_path: Path,
) -> None:
    materials = AuthMaterials(
        head_files={"security.py": FIXED_SOURCE},
        repo="example/factory-interpretation-cache",
        head_revision="head",
    )
    root = tmp_path / "summaries"

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

    items = second.route_summary_index.summaries[
        "security.py"
    ].dependency_factory_interpretations
    assert len(items) == 1
    interpretation = items[0].term.interpretation
    assert interpretation is not None
    assert interpretation.decoder == "pydantic.TypeAdapter.validate_python"
