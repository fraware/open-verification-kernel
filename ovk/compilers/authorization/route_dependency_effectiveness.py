"""Source-derived effectiveness contracts for direct FastAPI route dependencies.

This module proves one deliberately narrow fact:

    normal_return(require_auth) => bearer credential present and matches token

It does not infer authorization meaning from names. The governed Protected Effect
profile already supplies that policy meaning. This extractor only discharges the
separate fail-closed effectiveness obligation for a bounded source shape.

Unsupported syntax produces no evidence. It never manufactures a negative proof
or a PASS result.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping

from ovk.core.assurance_ir import GuardEffectivenessEvidence, SemanticOrigin
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_EXTRACTOR_ID = "assurance.fastapi.route_dependency_effectiveness.ast_v1"
_EXTRACTOR_VERSION = "0.1.0"


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_EXTRACTOR_ID,
        extractor_version=_EXTRACTOR_VERSION,
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _leaf_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dependency_parameter_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Return parameters populated by direct Depends/Security defaults."""

    names: set[str] = set()
    positional = list(function.args.posonlyargs) + list(function.args.args)
    defaults = list(function.args.defaults)
    if defaults:
        for argument, default in zip(positional[-len(defaults):], defaults):
            if (
                isinstance(default, ast.Call)
                and _leaf_name(default.func) in {"Depends", "Security"}
                and default.args
            ):
                names.add(argument.arg)

    for argument, default in zip(
        function.args.kwonlyargs,
        function.args.kw_defaults,
    ):
        if (
            isinstance(default, ast.Call)
            and _leaf_name(default.func) in {"Depends", "Security"}
            and default.args
        ):
            names.add(argument.arg)
    return names


def _raise_only_if(statement: ast.stmt) -> ast.AST | None:
    if (
        isinstance(statement, ast.If)
        and not statement.orelse
        and len(statement.body) == 1
        and isinstance(statement.body[0], ast.Raise)
    ):
        return statement.test
    return None


def _render_token_expression(node: ast.AST) -> str | None:
    """Return a bounded server-state expression used as the comparison token."""

    if not isinstance(node, (ast.Name, ast.Attribute)):
        return None
    return ast.unparse(node)


def _missing_token_guard(test: ast.AST) -> str | None:
    """Recognize a token-is-None fail-closed predicate."""

    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.Is)
        or len(test.comparators) != 1
    ):
        return None

    left = test.left
    right = test.comparators[0]

    def is_none(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value is None

    if is_none(right):
        return _render_token_expression(left)
    if is_none(left):
        return _render_token_expression(right)
    return None


def _missing_credential_parameter(
    node: ast.AST,
    dependency_parameters: set[str],
) -> str | None:
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, ast.Name)
        and node.operand.id in dependency_parameters
    ):
        return node.operand.id

    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Is)
        and len(node.comparators) == 1
    ):
        left = node.left
        right = node.comparators[0]
        if (
            isinstance(left, ast.Name)
            and left.id in dependency_parameters
            and isinstance(right, ast.Constant)
            and right.value is None
        ):
            return left.id
        if (
            isinstance(right, ast.Name)
            and right.id in dependency_parameters
            and isinstance(left, ast.Constant)
            and left.value is None
        ):
            return right.id
    return None


def _credential_projection(
    node: ast.AST,
    dependency_parameters: set[str],
) -> tuple[str, str] | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in dependency_parameters
    ):
        return node.value.id, node.attr
    return None


def _credential_mismatch_guard(
    test: ast.AST,
    dependency_parameters: set[str],
) -> tuple[str, str, str] | None:
    """Recognize missing-credential OR credential-attribute mismatch."""

    if (
        not isinstance(test, ast.BoolOp)
        or not isinstance(test.op, ast.Or)
        or len(test.values) != 2
    ):
        return None

    for missing_node, mismatch_node in (
        (test.values[0], test.values[1]),
        (test.values[1], test.values[0]),
    ):
        missing_parameter = _missing_credential_parameter(
            missing_node, dependency_parameters
        )
        if missing_parameter is None:
            continue

        if (
            not isinstance(mismatch_node, ast.Compare)
            or len(mismatch_node.ops) != 1
            or not isinstance(mismatch_node.ops[0], ast.NotEq)
            or len(mismatch_node.comparators) != 1
        ):
            continue

        left = mismatch_node.left
        right = mismatch_node.comparators[0]
        for credential_node, token_node in ((left, right), (right, left)):
            projection = _credential_projection(
                credential_node, dependency_parameters
            )
            if projection is None:
                continue
            parameter, attribute = projection
            if parameter != missing_parameter:
                continue
            token_expression = _render_token_expression(token_node)
            if token_expression is None:
                continue
            return parameter, attribute, token_expression

    return None


def _meaningful_body(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.stmt]:
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return body


def _infer_function_evidence(
    *,
    dependency_name: str,
    path: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> GuardEffectivenessEvidence | None:
    """Infer the bounded fail-closed bearer-match contract for one function."""

    dependency_parameters = _dependency_parameter_names(function)
    if not dependency_parameters:
        return None

    body = _meaningful_body(function)
    if not body:
        return None

    missing_token: tuple[str, ast.stmt] | None = None
    credential_guard: tuple[str, str, str, ast.stmt] | None = None

    for statement in body:
        test = _raise_only_if(statement)
        if test is None:
            return None

        token = _missing_token_guard(test)
        if token is not None:
            if missing_token is not None:
                return None
            missing_token = (token, statement)
            continue

        mismatch = _credential_mismatch_guard(test, dependency_parameters)
        if mismatch is not None:
            if credential_guard is not None:
                return None
            parameter, attribute, token_expression = mismatch
            credential_guard = (
                parameter,
                attribute,
                token_expression,
                statement,
            )
            continue

        return None

    if missing_token is None or credential_guard is None:
        return None

    token_expression, token_statement = missing_token
    (
        credential_parameter,
        credential_attribute,
        compared_token_expression,
        credential_statement,
    ) = credential_guard
    if token_expression != compared_token_expression:
        return None

    token_line = int(getattr(token_statement, "lineno", 0))
    credential_line = int(getattr(credential_statement, "lineno", 0))
    if token_line <= 0 or credential_line <= token_line:
        return None

    proof_payload = {
        "kind": "fail_closed_bearer_match_v1",
        "dependency_name": dependency_name,
        "path": path,
        "function": function.name,
        "credential_parameter": credential_parameter,
        "credential_attribute": credential_attribute,
        "token_expression": token_expression,
        "syntax": ast.dump(
            function, annotate_fields=True, include_attributes=False
        ),
    }
    evidence_id = "guard-effectiveness:" + content_digest(proof_payload)[:16]
    return GuardEffectivenessEvidence(
        evidence_id=evidence_id,
        dependency_name=dependency_name,
        evidence_kind="fail_closed_bearer_match_v1",
        credential_parameter=credential_parameter,
        credential_attribute=credential_attribute,
        token_expression=token_expression,
        assumptions=[
            (
                "The governed source profile assigns authorization meaning to "
                "this dependency for the declared effect/resource."
            ),
            (
                "Normal return implies the dependency credential is present "
                "and its configured credential attribute equals the guarded "
                "server token expression."
            ),
        ],
        origin=_origin(path, function),
    )


def infer_route_dependency_effectiveness(
    *,
    parsed_trees: Mapping[str, ast.Module],
    dependency_names: Iterable[str],
) -> list[GuardEffectivenessEvidence]:
    """Infer unique source-derived effectiveness evidence for configured guards."""

    definitions: dict[
        str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    ] = {}
    for path, tree in sorted(parsed_trees.items()):
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions.setdefault(node.name, []).append((path, node))

    evidence: list[GuardEffectivenessEvidence] = []
    for dependency_name in sorted(set(dependency_names)):
        leaf = dependency_name.rsplit(".", 1)[-1]
        candidates = definitions.get(leaf, [])
        if len(candidates) != 1:
            continue
        path, function = candidates[0]
        item = _infer_function_evidence(
            dependency_name=dependency_name,
            path=path,
            function=function,
        )
        if item is not None:
            evidence.append(item)

    return sorted(evidence, key=lambda item: item.evidence_id)
