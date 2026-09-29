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
from typing import Mapping

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
    has_control_flow: bool
    dependencies: tuple[DependencyParameterSummary, ...]
    calls: tuple[CallSummary, ...]
    origin: SemanticOrigin


@dataclass(frozen=True)
class RouteFileSummary:
    path: str
    source_digest: str
    handlers: tuple[RouteHandlerSummary, ...] = ()


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
        extractor_version="0.1.0",
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
) -> tuple[str, str] | None:
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
        return method.upper(), normalize_path("", route)
    return None


def _has_control_flow(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(node, _CONTROL_FLOW)
        for statement in handler.body
        for node in ast.walk(statement)
    )


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
        return ResourceIdentityTerm.literal(str(node.value))
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


def summarize_route_file(
    *,
    path: str,
    tree: ast.Module,
    source_digest: str,
) -> RouteFileSummary:
    handlers: list[RouteHandlerSummary] = []

    for handler in tree.body:
        if not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_decorator(handler)
        if route is None:
            continue
        method, route_path = route
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
                has_control_flow=_has_control_flow(handler),
                dependencies=_dependency_parameters(path, handler),
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
