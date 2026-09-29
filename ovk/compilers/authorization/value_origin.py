"""Explicit value-origin provenance for FastAPI handler values.

This module records where a value came from. It does not classify values as
trusted or untrusted and does not authorize bypasses.
"""

from __future__ import annotations

import ast

from ovk.core.assurance_ir import SemanticOrigin, ValueOriginEvidence
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_HTTP_PARAM_FORBIDDEN_ALIASES = frozenset(
    {
        "Annotated",
        "alias",
        "validation_alias",
        "serialization_alias",
    }
)


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.value_origin.ast_v1",
        extractor_version="0.1.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _evidence_id(kind: str, expression: str) -> str:
    return "vorigin:" + content_digest({"kind": kind, "expression": expression})[:16]


def _is_request_state_attribute(node: ast.AST) -> tuple[bool, str | None]:
    """Detect request.state.<attr> or getattr(request.state, \"attr\", ...)."""

    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "request"
        and node.value.attr == "state"
    ):
        return True, node.attr

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Attribute)
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "request"
        and node.args[0].attr == "state"
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return True, node.args[1].value

    return False, None


def _looks_like_config_name(name: str) -> bool:
    upper = name.upper()
    return (
        name.endswith("_CONFIG")
        or name.endswith("_SETTINGS")
        or name.startswith("CONFIG_")
        or name in {"settings", "config", "SETTINGS", "CONFIG"}
        or upper == name and "_" in name and not name.startswith("_")
    )


def classify_expression_origin(
    node: ast.AST,
    *,
    path: str,
    handler_param_names: frozenset[str],
) -> ValueOriginEvidence:
    """Classify one expression's origin without inventing trust."""

    rendered = ast.unparse(node)
    is_state, attr = _is_request_state_attribute(node)
    if is_state:
        return ValueOriginEvidence(
            evidence_id=_evidence_id("request_state_attribute", rendered),
            value_id=f"value:{attr or rendered}",
            origin_kind="request_state_attribute",
            source_expression=rendered,
            dependencies=[],
            origin=_origin(path, node),
        )

    if isinstance(node, ast.Constant):
        return ValueOriginEvidence(
            evidence_id=_evidence_id("literal_constant", rendered),
            value_id=f"value:literal:{rendered}",
            origin_kind="literal_constant",
            source_expression=rendered,
            dependencies=[],
            origin=_origin(path, node),
        )

    if isinstance(node, ast.Name):
        if node.id in handler_param_names:
            return ValueOriginEvidence(
                evidence_id=_evidence_id("externally_bound_http_value", rendered),
                value_id=f"value:param:{node.id}",
                origin_kind="externally_bound_http_value",
                source_expression=rendered,
                dependencies=[],
                origin=_origin(path, node),
            )
        if _looks_like_config_name(node.id):
            return ValueOriginEvidence(
                evidence_id=_evidence_id("server_configuration", rendered),
                value_id=f"value:config:{node.id}",
                origin_kind="server_configuration",
                source_expression=rendered,
                dependencies=[],
                origin=_origin(path, node),
            )
        return ValueOriginEvidence(
            evidence_id=_evidence_id("unknown_origin", rendered),
            value_id=f"value:unknown:{node.id}",
            origin_kind="unknown_origin",
            source_expression=rendered,
            dependencies=[],
            origin=_origin(path, node),
        )

    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if _looks_like_config_name(node.value.id):
            return ValueOriginEvidence(
                evidence_id=_evidence_id("server_configuration", rendered),
                value_id=f"value:config:{rendered}",
                origin_kind="server_configuration",
                source_expression=rendered,
                dependencies=[],
                origin=_origin(path, node),
            )

    # Derived / compound forms are recorded without inventing a stronger origin.
    return ValueOriginEvidence(
        evidence_id=_evidence_id("derived_value", rendered),
        value_id=f"value:derived:{content_digest(rendered)[:12]}",
        origin_kind="derived_value",
        source_expression=rendered,
        dependencies=[],
        origin=_origin(path, node),
    )


def _parameter_has_unsupported_binding(arg: ast.arg, default: ast.AST | None) -> bool:
    """Refuse alias / Annotated / dynamic FastAPI binding forms."""

    annotation = arg.annotation
    if annotation is not None:
        for child in ast.walk(annotation):
            if isinstance(child, ast.Name) and child.id in _HTTP_PARAM_FORBIDDEN_ALIASES:
                return True
            if isinstance(child, ast.Attribute) and child.attr in {
                "alias",
                "validation_alias",
            }:
                return True
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in {"Query", "Path", "Header", "Cookie", "Body", "Form"}
            ):
                for keyword in child.keywords:
                    if keyword.arg in {"alias", "validation_alias"}:
                        return True
    if default is not None:
        for child in ast.walk(default):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in {"Query", "Path", "Header", "Cookie", "Body", "Form"}
            ):
                for keyword in child.keywords:
                    if keyword.arg in {"alias", "validation_alias"}:
                        return True
            if isinstance(child, ast.Name) and child.id == "Annotated":
                return True
    return False


def extract_handler_value_origins(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str = "<handler>",
) -> tuple[ValueOriginEvidence, ...]:
    """Extract value-origin evidence for ordinary FastAPI handler parameters.

    Supported ordinary parameters (no alias/Annotated/dynamic binding) are
    classified as externally_bound_http_value. Unsupported binding forms yield
    unknown_origin. Function-name inference never invents origin.
    """

    found: list[ValueOriginEvidence] = []
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    defaults = list(handler.args.defaults)
    default_offset = len(positional) - len(defaults)

    # Skip typical self/cls if present on methods (route handlers rarely have them).
    start = 0
    if positional and positional[0].arg in {"self", "cls"}:
        start = 1

    for index, arg in enumerate(positional[start:], start=start):
        default = None
        if index >= default_offset:
            default = defaults[index - default_offset]
        # Depends/Security parameters are dependency results, not HTTP values.
        if (
            default is not None
            and isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id in {"Depends", "Security"}
        ):
            continue

        if _parameter_has_unsupported_binding(arg, default):
            found.append(
                ValueOriginEvidence(
                    evidence_id=_evidence_id("unknown_origin", arg.arg),
                    value_id=f"value:param:{arg.arg}",
                    origin_kind="unknown_origin",
                    source_expression=arg.arg,
                    dependencies=[],
                    origin=_origin(path, arg),
                )
            )
            continue

        found.append(
            ValueOriginEvidence(
                evidence_id=_evidence_id("externally_bound_http_value", arg.arg),
                value_id=f"value:param:{arg.arg}",
                origin_kind="externally_bound_http_value",
                source_expression=arg.arg,
                dependencies=[],
                origin=_origin(path, arg),
            )
        )

    # Also surface request.state reads inside the body.
    for node in ast.walk(handler):
        is_state, _attr = _is_request_state_attribute(node)
        if is_state:
            found.append(
                classify_expression_origin(
                    node,
                    path=path,
                    handler_param_names=frozenset(),
                )
            )

    # Deduplicate by evidence_id while preserving order.
    seen: set[str] = set()
    unique: list[ValueOriginEvidence] = []
    for item in found:
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        unique.append(item)
    return tuple(unique)


def extract_value_origins_from_source(
    source: str,
    *,
    path: str = "<handler>",
    function_name: str | None = None,
) -> tuple[ValueOriginEvidence, ...]:
    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if function_name is not None:
        functions = [node for node in functions if node.name == function_name]
    if not functions:
        raise ValueError("no function found for value-origin extraction")
    return extract_handler_value_origins(functions[0], path=path)
