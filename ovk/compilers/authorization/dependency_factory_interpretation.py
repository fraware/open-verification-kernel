"""Bounded source summaries for interpretations inside dependency factories.

This extractor records only parser provenance. It does not claim that the
returned dependency authorizes a resource, dominates a protected effect, or is
an effective guard. Those are separate proof obligations.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ovk.core.assurance_ir import SemanticOrigin
from ovk.core.models import SourceRange
from ovk.core.resource_identity import ResourceIdentityTerm


_EXTRACTOR_ID = "assurance.fastapi.dependency_factory_interpretation.ast_v1"
_EXTRACTOR_VERSION = "0.1.0"


@dataclass(frozen=True)
class DependencyFactoryInterpretationSummary:
    """One parsed path value produced inside a returned dependency callable."""

    factory_name: str
    returned_callable_name: str
    request_parameter: str
    path_parameter: str
    raw_symbol: str
    parsed_symbol: str
    term: ResourceIdentityTerm
    origin: SemanticOrigin


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_EXTRACTOR_ID,
        extractor_version=_EXTRACTOR_VERSION,
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(
                node,
                "end_lineno",
                getattr(node, "lineno", None),
            ),
        ),
    )


def _assignment(
    statement: ast.AST,
) -> tuple[str, ast.AST] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.value is not None
    ):
        return statement.target.id, statement.value
    return None


def _module_binding_count(tree: ast.Module, name: str) -> int:
    """Count explicit module-scope bindings without descending into callables."""

    count = 0
    for statement in tree.body:
        if isinstance(
            statement,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            count += int(statement.name == name)
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                count += int(bound == name)
            continue
        count += sum(
            1
            for node in ast.walk(statement)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        )
    return count


def _unique_direct_import(
    tree: ast.Module,
    *,
    module: str,
    name: str,
) -> bool:
    direct = 0
    for statement in tree.body:
        if not isinstance(statement, ast.ImportFrom):
            continue
        if statement.level != 0 or statement.module != module:
            continue
        for alias in statement.names:
            if alias.name == name and alias.asname is None:
                direct += 1
    return direct == 1 and _module_binding_count(tree, name) == 1


def _scope_binding_count(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> int:
    """Conservatively count local/enclosed bindings that could shadow a name."""

    count = sum(
        1
        for argument in (
            list(function.args.posonlyargs)
            + list(function.args.args)
            + list(function.args.kwonlyargs)
        )
        if argument.arg == name
    )
    if function.args.vararg is not None:
        count += int(function.args.vararg.arg == name)
    if function.args.kwarg is not None:
        count += int(function.args.kwarg.arg == name)

    for node in ast.walk(function):
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            count += 1
        elif isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            if node is not function:
                count += int(node.name == name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                count += int(bound == name)
    return count


def _returned_callable(
    factory: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Resolve a direct final return of one nested named callable."""

    body = list(factory.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if not body or not isinstance(body[-1], ast.Return):
        return None
    returned = body[-1].value
    if not isinstance(returned, ast.Name):
        return None

    candidates = [
        statement
        for statement in body[:-1]
        if isinstance(
            statement,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        )
        and statement.name == returned.id
    ]
    return candidates[0] if len(candidates) == 1 else None


def _request_parameter(
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    if not _unique_direct_import(
        tree,
        module="fastapi",
        name="Request",
    ):
        return None

    arguments = (
        list(function.args.posonlyargs)
        + list(function.args.args)
        + list(function.args.kwonlyargs)
    )
    candidates = [
        argument.arg
        for argument in arguments
        if isinstance(argument.annotation, ast.Name)
        and argument.annotation.id == "Request"
    ]
    return candidates[0] if len(candidates) == 1 else None


def _scope_store_count(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> int:
    return sum(
        1
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
    )


def _raw_path_bindings(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    request_parameter: str,
) -> dict[str, str]:
    """Return single-assignment request.path_params.get(...) aliases."""

    candidates: dict[str, list[str]] = {}
    for statement in function.body:
        assigned = _assignment(statement)
        if assigned is None:
            continue
        target, value = assigned
        if (
            not isinstance(value, ast.Call)
            or value.keywords
            or len(value.args) != 1
            or not isinstance(value.args[0], ast.Constant)
            or not isinstance(value.args[0].value, str)
            or not isinstance(value.func, ast.Attribute)
            or value.func.attr != "get"
            or not isinstance(value.func.value, ast.Attribute)
            or value.func.value.attr != "path_params"
            or not isinstance(value.func.value.value, ast.Name)
            or value.func.value.value.id != request_parameter
        ):
            continue
        candidates.setdefault(target, []).append(value.args[0].value)

    return {
        symbol: paths[0]
        for symbol, paths in candidates.items()
        if len(paths) == 1
        and _scope_store_count(function, symbol) == 1
    }


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_not_none(node: ast.AST, symbol: str) -> bool:
    if (
        not isinstance(node, ast.Compare)
        or len(node.ops) != 1
        or not isinstance(node.ops[0], ast.IsNot)
        or len(node.comparators) != 1
    ):
        return False
    left = node.left
    right = node.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == symbol
        and _is_none(right)
    ) or (
        isinstance(right, ast.Name)
        and right.id == symbol
        and _is_none(left)
    )


def _parser_call(
    node: ast.AST,
    *,
    raw_symbol: str,
) -> ast.Call | None:
    if isinstance(node, ast.Call):
        return node
    if (
        isinstance(node, ast.IfExp)
        and _is_not_none(node.test, raw_symbol)
        and _is_none(node.orelse)
        and isinstance(node.body, ast.Call)
    ):
        return node.body
    return None


def _nonnegativeint_adapters(tree: ast.Module) -> set[str]:
    if not (
        _unique_direct_import(
            tree,
            module="pydantic",
            name="TypeAdapter",
        )
        and _unique_direct_import(
            tree,
            module="pydantic",
            name="NonNegativeInt",
        )
    ):
        return set()

    candidates: set[str] = set()
    for statement in tree.body:
        assigned = _assignment(statement)
        if assigned is None:
            continue
        target, value = assigned
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "TypeAdapter"
            and len(value.args) == 1
            and not value.keywords
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == "NonNegativeInt"
            and _module_binding_count(tree, target) == 1
        ):
            candidates.add(target)
    return candidates


def _summary_for_call(
    *,
    path: str,
    tree: ast.Module,
    factory: ast.FunctionDef | ast.AsyncFunctionDef,
    returned: ast.FunctionDef | ast.AsyncFunctionDef,
    request_parameter: str,
    path_parameter: str,
    raw_symbol: str,
    parsed_symbol: str,
    call: ast.Call,
    adapters: set[str],
) -> DependencyFactoryInterpretationSummary | None:
    if (
        len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != raw_symbol
    ):
        return None

    term: ResourceIdentityTerm | None = None
    if (
        isinstance(call.func, ast.Name)
        and call.func.id == "int"
        and _module_binding_count(tree, "int") == 0
        and _scope_binding_count(factory, "int") == 0
        and _scope_binding_count(returned, "int") == 0
    ):
        term = ResourceIdentityTerm.interpreted_symbol(
            parsed_symbol,
            input_origin=f"request.path.{path_parameter}",
            decoder="python.int",
            output_type="builtins.int",
        )
    elif (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "validate_python"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in adapters
        and _scope_binding_count(factory, call.func.value.id) == 0
        and _scope_binding_count(returned, call.func.value.id) == 0
    ):
        term = ResourceIdentityTerm.interpreted_symbol(
            parsed_symbol,
            input_origin=f"request.path.{path_parameter}",
            decoder="pydantic.TypeAdapter.validate_python",
            output_type="pydantic.NonNegativeInt",
            constraints=("ge=0", "validation_mode=default"),
        )

    if term is None:
        return None
    return DependencyFactoryInterpretationSummary(
        factory_name=factory.name,
        returned_callable_name=returned.name,
        request_parameter=request_parameter,
        path_parameter=path_parameter,
        raw_symbol=raw_symbol,
        parsed_symbol=parsed_symbol,
        term=term,
        origin=_origin(path, call),
    )


def _factory_summaries(
    path: str,
    tree: ast.Module,
    factory: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[DependencyFactoryInterpretationSummary]:
    returned = _returned_callable(factory)
    if returned is None:
        return []
    request_parameter = _request_parameter(tree, returned)
    if request_parameter is None:
        return []

    raw_bindings = _raw_path_bindings(
        returned,
        request_parameter=request_parameter,
    )
    if not raw_bindings:
        return []

    adapters = _nonnegativeint_adapters(tree)
    found: list[DependencyFactoryInterpretationSummary] = []
    for node in ast.walk(returned):
        assigned = _assignment(node)
        if assigned is None:
            continue
        parsed_symbol, value = assigned
        for raw_symbol, path_parameter in sorted(raw_bindings.items()):
            call = _parser_call(value, raw_symbol=raw_symbol)
            if call is None:
                continue
            item = _summary_for_call(
                path=path,
                tree=tree,
                factory=factory,
                returned=returned,
                request_parameter=request_parameter,
                path_parameter=path_parameter,
                raw_symbol=raw_symbol,
                parsed_symbol=parsed_symbol,
                call=call,
                adapters=adapters,
            )
            if item is not None:
                found.append(item)

    unique: dict[
        tuple[str, str, str, str, str],
        DependencyFactoryInterpretationSummary,
    ] = {}
    for item in found:
        interpretation = item.term.interpretation
        assert interpretation is not None
        unique[
            (
                item.factory_name,
                item.returned_callable_name,
                item.path_parameter,
                item.parsed_symbol,
                interpretation.decoder,
            )
        ] = item
    return list(unique.values())


def summarize_dependency_factory_interpretations(
    *,
    path: str,
    tree: ast.Module,
) -> tuple[DependencyFactoryInterpretationSummary, ...]:
    """Summarize supported path interpretations in returned dependency callables."""

    found: list[DependencyFactoryInterpretationSummary] = []
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.extend(_factory_summaries(path, tree, statement))

    return tuple(
        sorted(
            found,
            key=lambda item: (
                item.factory_name,
                item.returned_callable_name,
                item.path_parameter,
                item.parsed_symbol,
                item.term.term_id,
            ),
        )
    )
