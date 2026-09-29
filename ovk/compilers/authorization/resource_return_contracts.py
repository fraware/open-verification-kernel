"""Restricted source inference for resource-return scope contracts.

The v1 rule recognizes a narrow rejecting-guard pattern:

    async def get(..., workspace_id: Optional[str] = None):
        ...
        if workspace_id is not None and resource.workspace_id != workspace_id:
            return None
        return resource

For a successful non-None return and a non-None supplied scope argument, the
method establishes:

    returned_resource.workspace_id == workspace_id

The inferencer deliberately ignores arbitrary functional behavior and does not
infer persistence-framework semantics such as primary-key identity.
"""

from __future__ import annotations

import ast

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.assurance_ir import ResourceReturnContract, SemanticOrigin
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_EXTRACTOR_ID = "assurance.python.resource_return_contracts.ast_v1"
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
        extractor_version="0.1.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {
        arg.arg
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
    }


def _returns_none(statements: list[ast.stmt]) -> bool:
    returns = [
        item
        for statement in statements
        for item in ast.walk(statement)
        if isinstance(item, ast.Return)
    ]
    return bool(returns) and all(item.value is None or _is_none(item.value) for item in returns)


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _contains_non_null_guard(test: ast.AST, parameter: str) -> bool:
    for item in ast.walk(test):
        if not isinstance(item, ast.Compare) or len(item.ops) != 1 or len(item.comparators) != 1:
            continue
        left = item.left
        right = item.comparators[0]
        op = item.ops[0]
        if isinstance(op, (ast.IsNot, ast.NotEq)):
            if isinstance(left, ast.Name) and left.id == parameter and _is_none(right):
                return True
            if isinstance(right, ast.Name) and right.id == parameter and _is_none(left):
                return True
    return False


def _scope_mismatch(test: ast.AST, returned_name: str) -> tuple[str, str] | None:
    """Return (scope_attribute, parameter) for resource.attr != parameter."""

    for item in ast.walk(test):
        if not isinstance(item, ast.Compare) or len(item.ops) != 1 or len(item.comparators) != 1:
            continue
        if not isinstance(item.ops[0], ast.NotEq):
            continue

        pairs = ((item.left, item.comparators[0]), (item.comparators[0], item.left))
        for attribute_node, parameter_node in pairs:
            if (
                isinstance(attribute_node, ast.Attribute)
                and isinstance(attribute_node.value, ast.Name)
                and attribute_node.value.id == returned_name
                and isinstance(parameter_node, ast.Name)
            ):
                return attribute_node.attr, parameter_node.id
    return None


def _top_level_success_return(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[int, str] | None:
    successes: list[tuple[int, str]] = []
    for index, statement in enumerate(node.body):
        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Name):
            successes.append((index, statement.value.id))
    if len(successes) != 1:
        return None

    non_none_returns = [
        item
        for statement in node.body
        for item in ast.walk(statement)
        if isinstance(item, ast.Return)
        and item.value is not None
        and not _is_none(item.value)
    ]
    if len(non_none_returns) != 1:
        return None
    return successes[0]


def _infer_method_contract(
    *,
    path: str,
    class_name: str,
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ResourceReturnContract | None:
    if any(
        isinstance(item, _UNSUPPORTED_CONTROL_FLOW)
        for statement in method.body
        for item in ast.walk(statement)
    ):
        return None

    success = _top_level_success_return(method)
    if success is None:
        return None
    success_index, returned_name = success
    parameters = _function_parameters(method)

    candidates: list[tuple[str, str, bool, ast.If]] = []
    for index, statement in enumerate(method.body):
        if index >= success_index or not isinstance(statement, ast.If):
            continue
        if not _returns_none(statement.body):
            continue
        mismatch = _scope_mismatch(statement.test, returned_name)
        if mismatch is None:
            continue
        scope_attribute, parameter = mismatch
        if parameter not in parameters:
            continue
        requires_non_null = _contains_non_null_guard(statement.test, parameter)
        candidates.append((scope_attribute, parameter, requires_non_null, statement))

    if len(candidates) != 1:
        return None

    scope_attribute, parameter, requires_non_null, guard = candidates[0]
    qualified_name = f"{class_name}.{method.name}"
    contract_id = (
        "contract:"
        + content_digest(
            {
                "qualified_name": qualified_name,
                "return_scope_parameter": parameter,
                "return_scope_attribute": scope_attribute,
                "requires_non_null_argument": requires_non_null,
                "path": path,
            }
        )[:16]
    )
    return ResourceReturnContract(
        contract_id=contract_id,
        qualified_name=qualified_name,
        return_scope_parameter=parameter,
        return_scope_attribute=scope_attribute,
        requires_non_null_argument=requires_non_null,
        origin=_origin(path, guard),
    )


def infer_resource_return_contracts(materials: AuthMaterials) -> list[ResourceReturnContract]:
    """Infer all v1 resource-return contracts from the head revision."""

    contracts: list[ResourceReturnContract] = []
    for path, source in sorted(materials.head_files.items()):
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            for statement in node.body:
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                contract = _infer_method_contract(
                    path=path,
                    class_name=node.name,
                    method=statement,
                )
                if contract is not None:
                    contracts.append(contract)
    return sorted(contracts, key=lambda item: item.contract_id)
