"""Tests for FastAPI value-origin provenance (#123)."""

from __future__ import annotations

from ovk.compilers.authorization.value_origin import (
    classify_expression_origin,
    extract_value_origins_from_source,
)
import ast


def test_ordinary_fastapi_param_is_external_http() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(bypass_filter: bool = False, item_id: str = "x"):
    return bypass_filter
""".strip()
    )
    kinds = {item.source_expression: item.origin_kind for item in evidence}
    assert kinds["bypass_filter"] == "externally_bound_http_value"
    assert kinds["item_id"] == "externally_bound_http_value"


def test_literal_and_config_kinds() -> None:
    lit = classify_expression_origin(
        ast.parse("True", mode="eval").body,
        path="h.py",
        handler_param_names=frozenset(),
    )
    assert lit.origin_kind == "literal_constant"

    cfg = classify_expression_origin(
        ast.parse("SETTINGS.debug", mode="eval").body,
        path="h.py",
        handler_param_names=frozenset(),
    )
    assert cfg.origin_kind == "server_configuration"


def test_request_state_is_not_trusted() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(request):
    return request.state.bypass_filter
""".strip()
    )
    state = [item for item in evidence if item.origin_kind == "request_state_attribute"]
    assert state
    assert "request.state.bypass_filter" in state[0].source_expression


def test_getattr_request_state() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(request):
    return getattr(request.state, "bypass_filter", False)
""".strip()
    )
    state = [item for item in evidence if item.origin_kind == "request_state_attribute"]
    assert state


def test_alias_param_refused_as_unknown() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(bypass_filter: bool = Query(False, alias="bypass")):
    return bypass_filter
""".strip()
    )
    by_name = {item.source_expression: item for item in evidence}
    assert by_name["bypass_filter"].origin_kind == "unknown_origin"


def test_function_name_does_not_invent_origin() -> None:
    evidence = extract_value_origins_from_source(
        """
def apparently_safe_admin_only(flag):
    return flag
""".strip()
    )
    assert all(item.origin_kind != "server_configuration" for item in evidence)
    assert evidence[0].origin_kind == "externally_bound_http_value"


def test_annotated_query_param_refused_as_unknown() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(bypass_filter: Annotated[bool, Query()] = False):
    return bypass_filter
""".strip()
    )
    by_name = {item.source_expression: item for item in evidence}
    assert by_name["bypass_filter"].origin_kind == "unknown_origin"


def test_kwargs_does_not_invent_http_origin() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(**kwargs):
    return kwargs.get("bypass_filter")
""".strip()
    )
    assert evidence == ()


def test_derived_expression_is_derived_not_trusted() -> None:
    derived = classify_expression_origin(
        ast.parse("flag or SETTINGS.debug", mode="eval").body,
        path="h.py",
        handler_param_names=frozenset({"flag"}),
    )
    assert derived.origin_kind == "derived_value"

def test_fastapi_attribute_query_alias_is_unknown() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(bypass: bool = fastapi.Query(False, alias="b")):
    return bypass
""".strip()
    )
    by_name = {item.source_expression: item for item in evidence}
    assert by_name["bypass"].origin_kind == "unknown_origin"


def test_typing_annotated_attribute_is_unknown() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(bypass: typing.Annotated[bool, Query()] = False):
    return bypass
""".strip()
    )
    by_name = {item.source_expression: item for item in evidence}
    assert by_name["bypass"].origin_kind == "unknown_origin"
