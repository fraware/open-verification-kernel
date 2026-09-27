"""Content-addressed FastAPI route syntax summaries.

These summaries preserve only source syntax facts needed by the bounded
dependency/effect source profile. They deliberately do not embed policy/profile
meaning or resolved function-contract semantics.

Unchanged source files can therefore reuse their route summaries across
revisions, while each compile rebinds those summaries against the current
FastApiDependencyEffectProfile and current FunctionContract set.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Literal, Mapping

from ovk.compilers.authorization.base import normalize_path
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.assurance_ir import SemanticOrigin
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange
from ovk.core.resource_identity import ResourceIdentityTerm


_EXTRACTOR_ID = "assurance.fastapi.dependency_effects.ast_v1"
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_CONTROL_FLOW = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.With,
    ast.AsyncWith,
)


@dataclass(frozen=True)
class ExpressionSummary:
    rendered: str
    term: ResourceIdentityTerm | None
    provably_non_null: bool
    origin: SemanticOrigin


@dataclass(frozen=True)
class DependencyParameterSummary:
    parameter_name: str
    dependency_name: str
    origin: SemanticOrigin


@dataclass(frozen=True)
class RouteDependencySummary:
    """Direct Depends/Security dependency inherited by one FastAPI route."""

    full_name: str
    leaf_name: str | None
    source_kind: Literal[
        "route_decorator",
        "router_constructor",
        "include_router",
    ]
    origin: SemanticOrigin


@dataclass(frozen=True)
class ModuleImportSummary:
    """Direct absolute module import usable for cross-file resolution."""

    local_name: str
    module_name: str


@dataclass(frozen=True)
class IncludeRouterCallSummary:
    """Profile-independent static FastAPI include_router syntax fact."""

    app_symbol: str
    module_alias: str
    router_symbol: str
    dependencies: tuple[RouteDependencySummary, ...] | None
    origin: SemanticOrigin


@dataclass(frozen=True)
class OwnershipAssertionSummary:
    """Profile-independent syntax summary for a fail-closed ownership check."""

    loader_full_name: str
    loader_leaf_name: str | None
    loaded_resource_symbol: str
    resource_identity_attribute: str
    resource_key: ExpressionSummary
    owner_attribute: str
    principal_expression: ExpressionSummary
    principal_attribute: str
    presence_test: str
    origin: SemanticOrigin

    @property
    def line(self) -> int:
        source_range = self.origin.source_range
        return int(source_range.start_line or 0) if source_range is not None else 0


@dataclass(frozen=True)
class CallSummary:
    full_name: str
    leaf_name: str | None
    resolved_qualified_name: str | None
    positional_arguments: tuple[ExpressionSummary, ...]
    keyword_arguments: tuple[tuple[str, ExpressionSummary], ...]
    origin: SemanticOrigin

    def keyword(self, name: str) -> ExpressionSummary | None:
        for key, value in self.keyword_arguments:
            if key == name:
                return value
        return None

    @property
    def line(self) -> int:
        source_range = self.origin.source_range
        return int(source_range.start_line or 0) if source_range is not None else 0


@dataclass(frozen=True)
class RouteHandlerSummary:
    handler_name: str
    method: str
    route_path: str
    router_symbol: str | None
    has_control_flow: bool
    unsupported_control_flow_lines: tuple[int, ...]
    dependencies: tuple[DependencyParameterSummary, ...]
    route_dependencies: tuple[RouteDependencySummary, ...]
    ownership_assertions: tuple[OwnershipAssertionSummary, ...]
    calls: tuple[CallSummary, ...]
    origin: SemanticOrigin


@dataclass(frozen=True)
class RouteFileSummary:
    path: str
    source_digest: str
    handlers: tuple[RouteHandlerSummary, ...] = ()
    apirouter_symbols: tuple[str, ...] = ()
    module_imports: tuple[ModuleImportSummary, ...] = ()
    include_router_calls: tuple[IncludeRouterCallSummary, ...] = ()


@dataclass(frozen=True)
class RouteSummaryIndex:
    summaries: dict[str, RouteFileSummary] = field(default_factory=dict)
    source_digests: dict[str, str] = field(default_factory=dict)
    fresh_summary_count: int = 0
    reused_summary_count: int = 0


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_EXTRACTOR_ID,
        extractor_version="0.6.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _name_of(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _route_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str, ast.Call, str | None] | None:
    for decorator in node.decorator_list:
        if (
            not isinstance(decorator, ast.Call)
            or not isinstance(decorator.func, ast.Attribute)
        ):
            continue
        method = decorator.func.attr.lower()
        if method not in _HTTP_METHODS or not decorator.args:
            continue
        route = _const_str(decorator.args[0])
        if route is None:
            continue
        receiver = decorator.func.value
        router_symbol = receiver.id if isinstance(receiver, ast.Name) else None
        return (
            method.upper(),
            normalize_path("", route),
            decorator,
            router_symbol,
        )
    return None


def _direct_dependencies(
    path: str,
    owner: ast.Call,
    *,
    source_kind: Literal["route_decorator", "router_constructor"],
) -> tuple[RouteDependencySummary, ...]:
    """Return direct Depends/Security declarations from one static owner call."""

    dependencies_node: ast.AST | None = None
    for keyword in owner.keywords:
        if keyword.arg == "dependencies":
            dependencies_node = keyword.value
            break

    if not isinstance(dependencies_node, (ast.List, ast.Tuple)):
        return ()

    found: list[RouteDependencySummary] = []
    for item in dependencies_node.elts:
        if (
            not isinstance(item, ast.Call)
            or _name_of(item.func) not in {"Depends", "Security"}
            or not item.args
        ):
            continue
        target = item.args[0]
        if not isinstance(target, (ast.Name, ast.Attribute)):
            continue
        found.append(
            RouteDependencySummary(
                full_name=ast.unparse(target),
                leaf_name=_name_of(target),
                source_kind=source_kind,
                origin=_origin(path, item),
            )
        )
    return tuple(found)


def _has_direct_fastapi_import(
    tree: ast.Module,
    name: str,
) -> bool:
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "fastapi"
        and statement.level == 0
        and any(
            alias.name == name and alias.asname is None
            for alias in statement.names
        )
        for statement in tree.body
    )


def _unique_constructor_symbols(
    tree: ast.Module,
    *,
    constructor: str,
) -> set[str]:
    if not _has_direct_fastapi_import(tree, constructor):
        return set()

    assignments: dict[str, int] = {}
    candidates: set[str] = set()
    for statement in tree.body:
        target: ast.Name | None = None
        value: ast.AST | None = None
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            target = statement.targets[0]
            value = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
        ):
            target = statement.target
            value = statement.value

        if target is None:
            continue
        assignments[target.id] = assignments.get(target.id, 0) + 1
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == constructor
        ):
            candidates.add(target.id)

    return {
        name
        for name in candidates
        if assignments.get(name) == 1
    }


def _module_import_summaries(
    tree: ast.Module,
) -> tuple[ModuleImportSummary, ...]:
    found: list[ModuleImportSummary] = []
    for statement in tree.body:
        if (
            not isinstance(statement, ast.ImportFrom)
            or statement.level != 0
            or not statement.module
        ):
            continue
        for alias in statement.names:
            if alias.name == "*":
                continue
            found.append(
                ModuleImportSummary(
                    local_name=alias.asname or alias.name,
                    module_name=f"{statement.module}.{alias.name}",
                )
            )
    return tuple(
        sorted(
            found,
            key=lambda item: (item.local_name, item.module_name),
        )
    )


def _include_router_dependencies(
    path: str,
    tree: ast.Module,
    call: ast.Call,
) -> tuple[RouteDependencySummary, ...] | None:
    values = [
        keyword.value
        for keyword in call.keywords
        if keyword.arg == "dependencies"
    ]
    if len(values) != 1:
        return None
    node = values[0]
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None

    found: list[RouteDependencySummary] = []
    for item in node.elts:
        if (
            not isinstance(item, ast.Call)
            or not isinstance(item.func, ast.Name)
            or item.func.id not in {"Depends", "Security"}
            or not _has_direct_fastapi_import(tree, item.func.id)
            or len(item.args) != 1
            or item.keywords
            or not isinstance(item.args[0], (ast.Name, ast.Attribute))
        ):
            return None
        target = item.args[0]
        found.append(
            RouteDependencySummary(
                full_name=ast.unparse(target),
                leaf_name=_name_of(target),
                source_kind="include_router",
                origin=_origin(path, item),
            )
        )

    return tuple(
        sorted(
            found,
            key=lambda item: (item.full_name, item.leaf_name or ""),
        )
    )


def _include_router_call_summaries(
    path: str,
    tree: ast.Module,
) -> tuple[IncludeRouterCallSummary, ...]:
    app_symbols = _unique_constructor_symbols(
        tree,
        constructor="FastAPI",
    )
    if not app_symbols:
        return ()

    found: list[IncludeRouterCallSummary] = []
    for statement in tree.body:
        if not isinstance(statement, ast.Expr):
            continue
        call = statement.value
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != "include_router"
            or not isinstance(call.func.value, ast.Name)
            or call.func.value.id not in app_symbols
            or not call.args
            or not isinstance(call.args[0], ast.Attribute)
            or not isinstance(call.args[0].value, ast.Name)
        ):
            continue

        found.append(
            IncludeRouterCallSummary(
                app_symbol=call.func.value.id,
                module_alias=call.args[0].value.id,
                router_symbol=call.args[0].attr,
                dependencies=_include_router_dependencies(
                    path,
                    tree,
                    call,
                ),
                origin=_origin(path, call),
            )
        )

    return tuple(
        sorted(
            found,
            key=lambda item: (
                item.module_alias,
                item.router_symbol,
                item.origin.source_range.start_line
                if item.origin.source_range is not None
                and item.origin.source_range.start_line is not None
                else 0,
            ),
        )
    )


def _router_constructor_dependencies(
    path: str,
    tree: ast.Module,
) -> dict[str, tuple[RouteDependencySummary, ...]]:
    """Return dependencies for uniquely assigned top-level APIRouter symbols.

    The supported inheritance form is deliberately narrow:

        router = APIRouter(dependencies=[Depends(require_auth)])

    Any second top-level assignment to the same symbol makes the binding
    ambiguous and suppresses inherited dependency semantics for that symbol.
    """

    valid_symbols = _unique_constructor_symbols(
        tree,
        constructor="APIRouter",
    )
    candidates: dict[str, tuple[RouteDependencySummary, ...]] = {}

    for statement in tree.body:
        target: ast.Name | None = None
        value: ast.AST | None = None
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            target = statement.targets[0]
            value = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
        ):
            target = statement.target
            value = statement.value

        if (
            target is None
            or target.id not in valid_symbols
            or not isinstance(value, ast.Call)
            or not isinstance(value.func, ast.Name)
            or value.func.id != "APIRouter"
        ):
            continue
        candidates[target.id] = _direct_dependencies(
            path,
            value,
            source_kind="router_constructor",
        )

    return candidates

def _route_dependencies(
    path: str,
    decorator: ast.Call,
    *,
    inherited: tuple[RouteDependencySummary, ...] = (),
) -> tuple[RouteDependencySummary, ...]:
    """Combine inherited router dependencies with direct route dependencies."""

    combined: dict[tuple[str, str | None], RouteDependencySummary] = {
        (item.full_name, item.leaf_name): item
        for item in inherited
    }
    for item in _direct_dependencies(
        path,
        decorator,
        source_kind="route_decorator",
    ):
        combined[(item.full_name, item.leaf_name)] = item

    return tuple(
        sorted(
            combined.values(),
            key=lambda item: (
                item.full_name,
                item.leaf_name or "",
                item.source_kind,
            ),
        )
    )


def _is_supported_fail_fast_none_guard(statement: ast.stmt) -> bool:
    """Return whether a statement only removes a null-valued continuing path.

    The supported form is deliberately narrow:

        if resource is None:
            raise ...

    The continuing path has exactly the same authorization/resource relations
    the extractor models, so ignoring this terminating branch does not create a
    new successful path.
    """
    if (
        not isinstance(statement, ast.If)
        or statement.orelse
        or len(statement.body) != 1
        or not isinstance(statement.body[0], ast.Raise)
    ):
        return False
    test = statement.test
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.Is)
        or len(test.comparators) != 1
    ):
        return False

    left = test.left
    right = test.comparators[0]

    def _is_none(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value is None

    def _is_resource_expression(node: ast.AST) -> bool:
        return isinstance(node, (ast.Name, ast.Attribute, ast.Subscript))

    return (
        _is_resource_expression(left) and _is_none(right)
    ) or (
        _is_none(left) and _is_resource_expression(right)
    )


def _ownership_guard_shape(
    statement: ast.stmt,
) -> tuple[str, str, ast.AST, str, str] | None:
    """Return the narrow fail-closed ownership-check syntax, if present.

    Supported continuing-path forms are:

        if resource and resource.owner != principal.id:
            raise ...

        if resource is not None and resource.owner != principal.id:
            raise ...

    The result is purely syntactic and carries no authorization meaning until a
    governed profile binds the loader and attributes.
    """

    if (
        not isinstance(statement, ast.If)
        or statement.orelse
        or len(statement.body) != 1
        or not isinstance(statement.body[0], ast.Raise)
        or not isinstance(statement.test, ast.BoolOp)
        or not isinstance(statement.test.op, ast.And)
        or len(statement.test.values) != 2
    ):
        return None

    values = list(statement.test.values)

    def presence(node: ast.AST) -> tuple[str, str] | None:
        if isinstance(node, ast.Name):
            return node.id, "truthy"
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.IsNot)
            and len(node.comparators) == 1
        ):
            left = node.left
            right = node.comparators[0]
            if (
                isinstance(left, ast.Name)
                and isinstance(right, ast.Constant)
                and right.value is None
            ):
                return left.id, "is_not_none"
            if (
                isinstance(right, ast.Name)
                and isinstance(left, ast.Constant)
                and left.value is None
            ):
                return right.id, "is_not_none"
        return None

    for presence_node, mismatch_node in (
        (values[0], values[1]),
        (values[1], values[0]),
    ):
        present = presence(presence_node)
        if present is None:
            continue
        loaded_symbol, presence_test = present

        if (
            not isinstance(mismatch_node, ast.Compare)
            or len(mismatch_node.ops) != 1
            or not isinstance(mismatch_node.ops[0], ast.NotEq)
            or len(mismatch_node.comparators) != 1
        ):
            continue

        left = mismatch_node.left
        right = mismatch_node.comparators[0]

        def loaded_owner(node: ast.AST) -> str | None:
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == loaded_symbol
            ):
                return node.attr
            return None

        left_owner = loaded_owner(left)
        right_owner = loaded_owner(right)
        if left_owner is not None and isinstance(right, ast.Attribute):
            return (
                loaded_symbol,
                left_owner,
                right,
                right.attr,
                presence_test,
            )
        if right_owner is not None and isinstance(left, ast.Attribute):
            return (
                loaded_symbol,
                right_owner,
                left,
                left.attr,
                presence_test,
            )
    return None


def _is_supported_fail_closed_ownership_guard(statement: ast.stmt) -> bool:
    return _ownership_guard_shape(statement) is not None


def _unsupported_control_flow_lines(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[int, ...]:
    """Return top-level statement lines containing unsupported control flow.

    These source locations support protected-effect-local coverage: unsupported
    control flow before a sink affects that sink's path, while unrelated
    control flow in another handler or after the sink does not.
    """

    lines: list[int] = []
    for statement in handler.body:
        if _is_supported_fail_fast_none_guard(statement):
            continue
        if _is_supported_fail_closed_ownership_guard(statement):
            continue
        if any(isinstance(node, _CONTROL_FLOW) for node in ast.walk(statement)):
            lines.append(int(getattr(statement, "lineno", 0)))
    return tuple(sorted(set(lines)))


def _has_control_flow(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return bool(_unsupported_control_flow_lines(handler))


def _body_calls(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    calls = [
        node
        for statement in handler.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
    ]
    return sorted(
        calls,
        key=lambda item: (
            getattr(item, "lineno", 0),
            getattr(item, "col_offset", 0),
        ),
    )


def _depends_name(node: ast.AST | None) -> str | None:
    if (
        not isinstance(node, ast.Call)
        or _name_of(node.func) not in {"Depends", "Security"}
    ):
        return None
    if not node.args:
        return None
    return _name_of(node.args[0])


def _dependency_parameters(
    path: str,
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[DependencyParameterSummary, ...]:
    found: list[DependencyParameterSummary] = []
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    defaults = list(handler.args.defaults)
    if defaults:
        for arg, default in zip(positional[-len(defaults):], defaults):
            dep = _depends_name(default)
            if dep:
                found.append(
                    DependencyParameterSummary(
                        parameter_name=arg.arg,
                        dependency_name=dep,
                        origin=_origin(path, default),
                    )
                )

    for arg, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        dep = _depends_name(default)
        if dep and default is not None:
            found.append(
                DependencyParameterSummary(
                    parameter_name=arg.arg,
                    dependency_name=dep,
                    origin=_origin(path, default),
                )
            )
    return tuple(found)


def _constructor_aliases(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in handler.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if (
            not isinstance(target, ast.Name)
            or not isinstance(statement.value, ast.Call)
        ):
            continue
        constructor = _name_of(statement.value.func)
        if constructor:
            aliases[target.id] = constructor
    return aliases


def _resolved_call_qualified_name(
    call: ast.Call,
    constructor_aliases: dict[str, str],
) -> str | None:
    if not isinstance(call.func, ast.Attribute):
        return None

    receiver = call.func.value
    if isinstance(receiver, ast.Name):
        constructor = constructor_aliases.get(receiver.id)
        if constructor:
            return f"{constructor}.{call.func.attr}"

    if isinstance(receiver, ast.Call):
        constructor = _name_of(receiver.func)
        if constructor:
            return f"{constructor}.{call.func.attr}"
    return None


def _annotation_excludes_none(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    rendered = ast.unparse(annotation)
    return "None" not in rendered and "Optional" not in rendered


def _provably_non_null_parameters(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    result: set[str] = set()
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    default_count = len(handler.args.defaults)
    required_positional = (
        positional[:-default_count]
        if default_count
        else positional
    )
    for arg in required_positional:
        if _annotation_excludes_none(arg.annotation):
            result.add(arg.arg)

    for arg, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        if default is None and _annotation_excludes_none(arg.annotation):
            result.add(arg.arg)
    return result


def _symbol_term(node: ast.AST) -> ResourceIdentityTerm | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, bool)):
        rendered = str(node.value)
        if not rendered.strip():
            return None
        return ResourceIdentityTerm.literal(rendered)
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ResourceIdentityTerm.symbol(ast.unparse(node))
    return None


def _expression_summary(
    path: str,
    node: ast.AST,
    *,
    non_null_parameters: set[str],
) -> ExpressionSummary:
    return ExpressionSummary(
        rendered=ast.unparse(node),
        term=_symbol_term(node),
        provably_non_null=(
            (isinstance(node, ast.Constant) and node.value is not None)
            or (
                isinstance(node, ast.Name)
                and node.id in non_null_parameters
            )
        ),
        origin=_origin(path, node),
    )


def _unwrap_call(node: ast.AST) -> ast.Call | None:
    if isinstance(node, ast.Await):
        node = node.value
    return node if isinstance(node, ast.Call) else None


def _loader_resource_candidates(
    path: str,
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    non_null_parameters: set[str],
) -> dict[str, list[tuple[str, str | None, str, ExpressionSummary, int]]]:
    """Summarize top-level loaded-resource assignments by route key.

    The syntax rule is deliberately narrow: a named local receives a call whose
    nested expression contains where(Model.resource_attr == route_expression).
    Policy meaning is deferred to the governed profile.
    """

    result: dict[
        str,
        list[tuple[str, str | None, str, ExpressionSummary, int]],
    ] = {}

    for statement in handler.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue

        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(
                statement.targets[0],
                ast.Name,
            ):
                continue
            target = statement.targets[0]
            value = statement.value
        else:
            if not isinstance(statement.target, ast.Name):
                continue
            target = statement.target
            value = statement.value

        if value is None:
            continue
        outer = _unwrap_call(value)
        if outer is None:
            continue

        loader_full_name = ast.unparse(outer.func)
        loader_leaf_name = _name_of(outer.func)
        line = int(getattr(statement, "lineno", 0))

        for nested in ast.walk(outer):
            if (
                not isinstance(nested, ast.Call)
                or not isinstance(nested.func, ast.Attribute)
                or nested.func.attr != "where"
                or len(nested.args) != 1
            ):
                continue
            predicate = nested.args[0]
            if (
                not isinstance(predicate, ast.Compare)
                or len(predicate.ops) != 1
                or not isinstance(predicate.ops[0], ast.Eq)
                or len(predicate.comparators) != 1
            ):
                continue

            left = predicate.left
            right = predicate.comparators[0]
            pairs: list[tuple[ast.Attribute, ast.AST]] = []
            if isinstance(left, ast.Attribute) and not isinstance(
                right,
                ast.Attribute,
            ):
                pairs.append((left, right))
            if isinstance(right, ast.Attribute) and not isinstance(
                left,
                ast.Attribute,
            ):
                pairs.append((right, left))

            for model_attribute, resource_node in pairs:
                resource_summary = _expression_summary(
                    path,
                    resource_node,
                    non_null_parameters=non_null_parameters,
                )
                if resource_summary.term is None:
                    continue
                result.setdefault(target.id, []).append(
                    (
                        loader_full_name,
                        loader_leaf_name,
                        model_attribute.attr,
                        resource_summary,
                        line,
                    )
                )
    return result


def _ownership_assertion_summaries(
    path: str,
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    non_null_parameters: set[str],
) -> tuple[OwnershipAssertionSummary, ...]:
    loaders = _loader_resource_candidates(
        path,
        handler,
        non_null_parameters=non_null_parameters,
    )
    found: list[OwnershipAssertionSummary] = []

    for statement in handler.body:
        shape = _ownership_guard_shape(statement)
        if shape is None:
            continue
        (
            loaded_symbol,
            owner_attribute,
            principal_node,
            principal_attribute,
            presence_test,
        ) = shape
        statement_line = int(getattr(statement, "lineno", 0))
        principal = _expression_summary(
            path,
            principal_node,
            non_null_parameters=non_null_parameters,
        )
        if principal.term is None:
            continue

        for (
            loader_full_name,
            loader_leaf_name,
            resource_identity_attribute,
            resource_key,
            load_line,
        ) in loaders.get(loaded_symbol, []):
            if load_line >= statement_line:
                continue
            found.append(
                OwnershipAssertionSummary(
                    loader_full_name=loader_full_name,
                    loader_leaf_name=loader_leaf_name,
                    loaded_resource_symbol=loaded_symbol,
                    resource_identity_attribute=resource_identity_attribute,
                    resource_key=resource_key,
                    owner_attribute=owner_attribute,
                    principal_expression=principal,
                    principal_attribute=principal_attribute,
                    presence_test=presence_test,
                    origin=_origin(path, statement),
                )
            )

    return tuple(
        sorted(
            found,
            key=lambda item: (
                item.line,
                item.loaded_resource_symbol,
                item.resource_identity_attribute,
                item.owner_attribute,
                item.principal_expression.rendered,
            ),
        )
    )


def summarize_route_file(
    *,
    path: str,
    tree: ast.Module,
    source_digest: str,
) -> RouteFileSummary:
    handlers: list[RouteHandlerSummary] = []
    inherited_by_router = _router_constructor_dependencies(path, tree)

    for handler in tree.body:
        if not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_decorator(handler)
        if route is None:
            continue
        method, route_path, route_decorator, router_symbol = route
        aliases = _constructor_aliases(handler)
        non_null = _provably_non_null_parameters(handler)

        calls: list[CallSummary] = []
        for call in _body_calls(handler):
            keywords: list[tuple[str, ExpressionSummary]] = []
            for keyword in call.keywords:
                if keyword.arg is None:
                    continue
                keywords.append(
                    (
                        keyword.arg,
                        _expression_summary(
                            path,
                            keyword.value,
                            non_null_parameters=non_null,
                        ),
                    )
                )

            calls.append(
                CallSummary(
                    full_name=ast.unparse(call.func),
                    leaf_name=_name_of(call.func),
                    resolved_qualified_name=_resolved_call_qualified_name(
                        call,
                        aliases,
                    ),
                    positional_arguments=tuple(
                        _expression_summary(
                            path,
                            argument,
                            non_null_parameters=non_null,
                        )
                        for argument in call.args
                    ),
                    keyword_arguments=tuple(keywords),
                    origin=_origin(path, call),
                )
            )

        handlers.append(
            RouteHandlerSummary(
                handler_name=handler.name,
                method=method,
                route_path=route_path,
                router_symbol=router_symbol,
                has_control_flow=_has_control_flow(handler),
                unsupported_control_flow_lines=_unsupported_control_flow_lines(handler),
                dependencies=_dependency_parameters(path, handler),
                route_dependencies=_route_dependencies(
                    path,
                    route_decorator,
                    inherited=(
                        inherited_by_router.get(router_symbol, ())
                        if router_symbol is not None
                        else ()
                    ),
                ),
                ownership_assertions=_ownership_assertion_summaries(
                    path,
                    handler,
                    non_null_parameters=non_null,
                ),
                calls=tuple(calls),
                origin=_origin(path, handler),
            )
        )

    return RouteFileSummary(
        path=path,
        source_digest=source_digest,
        handlers=tuple(
            sorted(
                handlers,
                key=lambda item: (
                    item.method,
                    item.route_path,
                    item.handler_name,
                ),
            )
        ),
        apirouter_symbols=tuple(
            sorted(
                _unique_constructor_symbols(
                    tree,
                    constructor="APIRouter",
                )
            )
        ),
        module_imports=_module_import_summaries(tree),
        include_router_calls=_include_router_call_summaries(
            path,
            tree,
        ),
    )


def build_route_summary_index(
    materials: AuthMaterials,
    *,
    parsed_trees: Mapping[str, ast.Module],
    source_digests: Mapping[str, str] | None = None,
    reuse_from: RouteSummaryIndex | None = None,
) -> RouteSummaryIndex:
    digests = (
        dict(source_digests)
        if source_digests is not None
        else {
            path: content_digest(source)
            for path, source in sorted(materials.head_files.items())
        }
    )
    expected = {
        path: content_digest(source)
        for path, source in sorted(materials.head_files.items())
    }
    if digests != expected:
        raise ValueError(
            "route summary source digests do not match supplied head materials"
        )

    summaries: dict[str, RouteFileSummary] = {}
    fresh = 0
    reused = 0

    for path, tree in sorted(parsed_trees.items()):
        digest = digests.get(path)
        if digest is None:
            raise ValueError(f"missing source digest for parsed tree: {path}")

        prior = reuse_from.summaries.get(path) if reuse_from is not None else None
        if prior is not None and prior.source_digest == digest:
            summaries[path] = prior
            reused += 1
            continue

        summaries[path] = summarize_route_file(
            path=path,
            tree=tree,
            source_digest=digest,
        )
        fresh += 1

    return RouteSummaryIndex(
        summaries=summaries,
        source_digests=digests,
        fresh_summary_count=fresh,
        reused_summary_count=reused,
    )


def route_summary_index_matches_materials(
    summary_index: RouteSummaryIndex,
    materials: AuthMaterials,
) -> bool:
    expected = {
        path: content_digest(source)
        for path, source in sorted(materials.head_files.items())
    }
    return expected == summary_index.source_digests
