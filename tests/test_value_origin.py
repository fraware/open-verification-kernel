"""Tests for FastAPI value-origin provenance and bounded Name alias tracking."""

from __future__ import annotations

import ast

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority
from ovk.compilers.authorization.value_origin import (
    classify_expression_origin,
    classify_name_after_handler_bindings,
    extract_value_origins_from_source,
)


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


def test_literal_and_config_shaped_names_do_not_invent_trust() -> None:
    lit = classify_expression_origin(
        ast.parse("True", mode="eval").body,
        path="h.py",
        handler_param_names=frozenset(),
    )
    assert lit.origin_kind == "literal_constant"

    for expression in ("SETTINGS.debug", "settings.ALLOW"):
        evidence = classify_expression_origin(
            ast.parse(expression, mode="eval").body,
            path="h.py",
            handler_param_names=frozenset(),
        )
        assert evidence.origin_kind == "derived_value"


def test_bare_allcaps_name_is_unknown_not_server_configuration() -> None:
    """ALL_CAPS alone must not invent server_configuration provenance."""

    for bare in ("BYPASS_FILTER", "ALLOW_ALL", "DEBUG", "SETTINGS_ALLOW"):
        evidence = classify_expression_origin(
            ast.parse(bare, mode="eval").body,
            path="h.py",
            handler_param_names=frozenset(),
        )
        assert evidence.origin_kind == "unknown_origin", bare


def test_conventional_config_shaped_names_remain_unknown() -> None:
    for name in ("APP_SETTINGS", "SERVER_CONFIG", "CONFIG_FLAG"):
        evidence = classify_expression_origin(
            ast.parse(name, mode="eval").body,
            path="h.py",
            handler_param_names=frozenset(),
        )
        assert evidence.origin_kind == "unknown_origin", name


def test_settings_parameter_attribute_is_not_server_configuration() -> None:
    evidence = classify_expression_origin(
        ast.parse("settings.ALLOW", mode="eval").body,
        path="h.py",
        handler_param_names=frozenset({"settings"}),
    )
    assert evidence.origin_kind == "derived_value"


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


def test_simple_alias_of_request_state_survives() -> None:
    evidence = classify_name_after_handler_bindings(
        """
def handler(request):
    x = request.state.bypass_filter
    return x
""".strip(),
        name="x",
    )
    assert evidence.origin_kind == "request_state_attribute"
    assert evidence.dependencies


def test_simple_alias_of_http_param_survives() -> None:
    evidence = classify_name_after_handler_bindings(
        """
def handler(bypass_filter: bool = False):
    x = bypass_filter
    return x
""".strip(),
        name="x",
    )
    assert evidence.origin_kind == "externally_bound_http_value"
    assert evidence.dependencies


def test_aliased_http_param_write_is_client_controlled() -> None:
    """Closed-world write via alias must still see HTTP provenance."""

    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False):
    x = bypass_filter
    request.state.bypass_filter = x

def handler(request):
    if request.state.bypass_filter:
        return sink()
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_tuple_unpacking_alias_is_unknown() -> None:
    evidence = classify_name_after_handler_bindings(
        """
def handler(request):
    x, y = request.state.bypass_filter, True
    return x
""".strip(),
        name="x",
    )
    assert evidence.origin_kind == "unknown_origin"


def test_multi_target_assign_is_unknown() -> None:
    evidence = classify_name_after_handler_bindings(
        """
def handler(bypass_filter: bool = False):
    x = y = bypass_filter
    return x
""".strip(),
        name="x",
    )
    assert evidence.origin_kind == "unknown_origin"


def test_attribute_alias_of_request_state_is_unknown() -> None:
    """``state = request.state; state.f`` defeats bounded resolution."""

    evidence = classify_name_after_handler_bindings(
        """
def handler(request):
    state = request.state
    x = state.bypass_filter
    return x
""".strip(),
        name="x",
    )
    assert evidence.origin_kind == "unknown_origin"


def test_reassignment_after_use_is_unknown() -> None:
    evidence = classify_name_after_handler_bindings(
        """
def handler(request, bypass_filter: bool = False):
    x = request.state.bypass_filter
    if x:
        sink()
    x = bypass_filter
    return x
""".strip(),
        name="x",
    )
    assert evidence.origin_kind == "unknown_origin"


def test_extract_surfaces_proved_alias_evidence() -> None:
    evidence = extract_value_origins_from_source(
        """
def handler(bypass_filter: bool = False):
    x = bypass_filter
    return x
""".strip()
    )
    alias = [item for item in evidence if item.value_id == "value:alias:x"]
    assert alias
    assert alias[0].origin_kind == "externally_bound_http_value"


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


def test_branch_local_alias_rebind_is_poisoned_not_authorized() -> None:
    """Client alias must not become trusted via path-insensitive branch rebind."""

    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False, server_mode: bool = False):
    x = bypass_filter
    if server_mode:
        x = settings.ALLOW
    request.state.bypass_filter = x

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason in {
        "unresolved_write_origin",
        "unsupported_write_origin_mix",
    }
