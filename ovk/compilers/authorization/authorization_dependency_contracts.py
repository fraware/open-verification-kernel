"""Restricted source inference for authorization-dependency contracts.

The v1 rule recognizes one narrow fail-closed credential-equality shape:

    async def require_auth(credentials = Depends(...)):
        if not credentials or credentials.credentials != EXPECTED_TOKEN:
            raise HTTPException(...)
        # optional straight-line work
        return None  # optional final explicit return

For every normal completion of a function matching this rule:

    credentials is present
    and credentials.credentials == EXPECTED_TOKEN

The inference is deliberately conservative. It rejects:
- any explicit return before the rejecting guard;
- any nested/alternate return path;
- loops, try, match, with/async-with, or additional conditionals;
- dependency wrappers and delegated authorization helpers;
- comparison operators or expressions outside the bounded rule.

The contract proves only the source-level equality relation. A governed
Protected Effect profile must separately identify which credential expression
and authority expression are trusted for a route dependency.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

from ovk.core.assurance_ir import (
    AuthorizationDependencyContract,
    SemanticOrigin,
)
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_EXTRACTOR_ID = "assurance.python.authorization_dependency_contracts.ast_v1"
_EXTRACTOR_VERSION = "0.1.0"
_UNSUPPORTED_CONTROL_FLOW = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.With,
    ast.AsyncWith,
)


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


def _function_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    return {
        arg.arg
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
    }


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _presence_parameter(node: ast.AST) -> str | None:
    """Return the parameter proven present by falsity of this predicate."""

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        if isinstance(node.operand, ast.Name):
            return node.operand.id

    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and len(node.comparators) == 1
    ):
        left = node.left
        right = node.comparators[0]
        op = node.ops[0]
        if isinstance(op, (ast.Is, ast.Eq)):
            if isinstance(left, ast.Name) and _is_none(right):
                return left.id
            if isinstance(right, ast.Name) and _is_none(left):
                return right.id
    return None


def _credential_mismatch(
    node: ast.AST,
    *,
    parameter: str,
) -> tuple[str, str] | None:
    """Return (credential_expression, authority_expression) for a != b."""

    if (
        not isinstance(node, ast.Compare)
        or len(node.ops) != 1
        or not isinstance(node.ops[0], ast.NotEq)
        or len(node.comparators) != 1
    ):
        return None

    left = node.left
    right = node.comparators[0]

    def credential_expression(candidate: ast.AST) -> str | None:
        if (
            isinstance(candidate, ast.Attribute)
            and isinstance(candidate.value, ast.Name)
            and candidate.value.id == parameter
        ):
            return ast.unparse(candidate)
        return None

    left_credential = credential_expression(left)
    if left_credential is not None:
        if isinstance(right, (ast.Name, ast.Attribute, ast.Subscript)):
            return left_credential, ast.unparse(right)
        if isinstance(right, ast.Constant) and right.value is not None:
            rendered = str(right.value)
            if rendered.strip():
                return left_credential, ast.unparse(right)
        return None

    right_credential = credential_expression(right)
    if right_credential is not None:
        if isinstance(left, (ast.Name, ast.Attribute, ast.Subscript)):
            return right_credential, ast.unparse(left)
        if isinstance(left, ast.Constant) and left.value is not None:
            rendered = str(left.value)
            if rendered.strip():
                return right_credential, ast.unparse(left)
    return None


def _rejecting_guard(
    statement: ast.stmt,
    *,
    parameters: set[str],
) -> tuple[str, str] | None:
    """Return proved credential/authority equality for a fail-closed guard."""

    if (
        not isinstance(statement, ast.If)
        or statement.orelse
        or len(statement.body) != 1
        or not isinstance(statement.body[0], ast.Raise)
        or not isinstance(statement.test, ast.BoolOp)
        or not isinstance(statement.test.op, ast.Or)
        or len(statement.test.values) != 2
    ):
        return None

    first, second = statement.test.values
    for presence_node, mismatch_node in (
        (first, second),
        (second, first),
    ):
        parameter = _presence_parameter(presence_node)
        if parameter is None or parameter not in parameters:
            continue
        mismatch = _credential_mismatch(
            mismatch_node,
            parameter=parameter,
        )
        if mismatch is not None:
            return mismatch
    return None


def _contains_return(statement: ast.stmt) -> bool:
    return any(isinstance(node, ast.Return) for node in ast.walk(statement))


def _is_optional_final_return_none(
    statement: ast.stmt,
) -> bool:
    return (
        isinstance(statement, ast.Return)
        and (statement.value is None or _is_none(statement.value))
    )


def _infer_top_level_function_contract(
    *,
    path: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> AuthorizationDependencyContract | None:
    """Infer a direct v1 fail-closed credential-equality contract."""

    parameters = _function_parameters(function)
    candidates: list[tuple[int, str, str, ast.If]] = []

    for index, statement in enumerate(function.body):
        match = _rejecting_guard(
            statement,
            parameters=parameters,
        )
        if match is not None:
            credential_expression, authority_expression = match
            candidates.append(
                (
                    index,
                    credential_expression,
                    authority_expression,
                    statement,
                )
            )

    if len(candidates) != 1:
        return None

    guard_index, credential_expression, authority_expression, guard = (
        candidates[0]
    )

    for index, statement in enumerate(function.body):
        if index == guard_index:
            continue

        if isinstance(statement, ast.If):
            # Any additional conditional may introduce a normal-return path not
            # covered by the inferred credential predicate.
            return None
        if any(
            isinstance(node, _UNSUPPORTED_CONTROL_FLOW)
            for node in ast.walk(statement)
        ):
            return None

        if _contains_return(statement):
            if (
                index == len(function.body) - 1
                and index > guard_index
                and _is_optional_final_return_none(statement)
            ):
                continue
            return None

    contract_id = (
        "auth-contract:"
        + content_digest(
            {
                "qualified_name": function.name,
                "contract_kind": "credential_equality",
                "credential_expression": credential_expression,
                "authority_expression": authority_expression,
                "path": path,
            }
        )[:16]
    )
    return AuthorizationDependencyContract(
        contract_id=contract_id,
        qualified_name=function.name,
        credential_expression=credential_expression,
        authority_expression=authority_expression,
        origin=_origin(path, guard),
    )


def infer_authorization_dependency_contracts(
    *,
    parsed_trees: Mapping[str, ast.Module],
) -> list[AuthorizationDependencyContract]:
    """Infer direct authorization-dependency contracts from parsed sources."""

    contracts: dict[str, AuthorizationDependencyContract] = {}

    for path, tree in sorted(parsed_trees.items()):
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            contract = _infer_top_level_function_contract(
                path=path,
                function=node,
            )
            if contract is None:
                continue

            existing = contracts.get(contract.qualified_name)
            if (
                existing is not None
                and existing.contract_id != contract.contract_id
            ):
                # Ambiguous stable names are omitted instead of selecting one
                # source definition silently.
                contracts.pop(contract.qualified_name, None)
                continue
            contracts[contract.qualified_name] = contract

    return sorted(
        contracts.values(),
        key=lambda item: item.contract_id,
    )
