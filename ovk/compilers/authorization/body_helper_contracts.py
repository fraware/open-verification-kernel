"""Fail-closed body-authorization-helper implementation evidence (#148).

Profile declaration alone never establishes effectiveness. A helper becomes
established only when exactly one definition is found and that definition is a
fail-closed authorization check (raises / HTTPException on denial). No-op,
shadowed, and unresolved definitions stay unproved (Unknown > false PASS).
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class BodyHelperImplementationEvidence:
    helper_name: str
    path: str
    line: int
    status: str
    reason: str


def _is_http_exception_constructor(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "HTTPException"
    if isinstance(node, ast.Attribute):
        return node.attr == "HTTPException"
    return False


def _body_has_fail_closed_raise(body: list[ast.stmt]) -> bool:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Raise):
            if node.exc is None:
                return True
            if _is_http_exception_constructor(node.exc):
                return True
            if isinstance(node.exc, ast.Call) and _is_http_exception_constructor(
                node.exc.func
            ):
                return True
            if isinstance(node.exc, (ast.Name, ast.Attribute)):
                return True
    return False


def _body_is_noop(body: list[ast.stmt]) -> bool:
    """True when the body cannot deny (pass / return True / return None only)."""

    meaningful = [
        stmt
        for stmt in body
        if not isinstance(stmt, (ast.Pass, ast.Expr))
    ]
    if not meaningful:
        return True
    if len(meaningful) == 1 and isinstance(meaningful[0], ast.Return):
        value = meaningful[0].value
        if value is None:
            return True
        if isinstance(value, ast.Constant) and value.value in {True, None}:
            return True
    return False


def _collect_definitions(
    files: Mapping[str, str],
    *,
    helper_name: str,
) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    found: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for path, source in sorted(files.items()):
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            continue
        for node in tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == helper_name
            ):
                found.append((path, node))
    return found


def analyze_body_helper_implementation(
    files: Mapping[str, str],
    *,
    helper_name: str,
) -> BodyHelperImplementationEvidence:
    """Classify one profile helper's implementation for effectiveness."""

    definitions = _collect_definitions(files, helper_name=helper_name)
    if not definitions:
        return BodyHelperImplementationEvidence(
            helper_name=helper_name,
            path="<missing>",
            line=0,
            status="unproved",
            reason="helper_definition_missing",
        )
    if len(definitions) > 1:
        path, node = definitions[0]
        return BodyHelperImplementationEvidence(
            helper_name=helper_name,
            path=path,
            line=getattr(node, "lineno", 0) or 0,
            status="unproved",
            reason="helper_definition_shadowed",
        )
    path, node = definitions[0]
    if _body_is_noop(list(node.body)):
        return BodyHelperImplementationEvidence(
            helper_name=helper_name,
            path=path,
            line=getattr(node, "lineno", 0) or 0,
            status="unproved",
            reason="helper_implementation_noop",
        )
    if _body_has_fail_closed_raise(list(node.body)):
        return BodyHelperImplementationEvidence(
            helper_name=helper_name,
            path=path,
            line=getattr(node, "lineno", 0) or 0,
            status="established",
            reason="helper_fail_closed_raise",
        )
    return BodyHelperImplementationEvidence(
        helper_name=helper_name,
        path=path,
        line=getattr(node, "lineno", 0) or 0,
        status="unproved",
        reason="helper_implementation_unproved",
    )
