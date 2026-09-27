"""Bounded cross-file FastAPI include_router dependency inheritance.

This module extracts static source facts needed to attach dependencies from an
app.include_router(module.router, dependencies=[Depends(require_auth)]) call to
routes declared on the referenced APIRouter in another selected source file.

It does not mutate the content-addressed per-file route summary. Cross-file
attachment identity is computed separately so an unchanged route file is
rebound when its include_router security context changes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Mapping

from ovk.compilers.authorization.fastapi_route_summary import (
    RouteDependencySummary,
)
from ovk.core.assurance_ir import SemanticOrigin
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_EXTRACTOR_ID = "assurance.fastapi.include_router_dependencies.ast_v1"
_EXTRACTOR_VERSION = "0.1.0"


@dataclass(frozen=True)
class IncludeRouterDependencyIndex:
    """Cross-file inherited dependencies keyed by target file/router symbol."""

    dependencies_by_target: dict[
        str,
        dict[str, tuple[RouteDependencySummary, ...]],
    ] = field(default_factory=dict)
    attachment_digests: dict[str, str] = field(default_factory=dict)

    def dependencies_for(
        self,
        *,
        path: str,
        router_symbol: str | None,
    ) -> tuple[RouteDependencySummary, ...]:
        if router_symbol is None:
            return ()
        return self.dependencies_by_target.get(path, {}).get(
            router_symbol,
            (),
        )

    def digest_for(self, path: str) -> str:
        return self.attachment_digests.get(
            path,
            content_digest([]),
        )


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


def _leaf_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _has_direct_from_import(
    tree: ast.Module,
    *,
    module: str,
    name: str,
) -> bool:
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == module
        and statement.level == 0
        and any(
            alias.name == name and alias.asname is None
            for alias in statement.names
        )
        for statement in tree.body
    )


def _unique_fastapi_app_symbols(tree: ast.Module) -> set[str]:
    """Return uniquely bound top-level FastAPI instance symbols."""

    if not _has_direct_from_import(
        tree,
        module="fastapi",
        name="FastAPI",
    ):
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
            and value.func.id == "FastAPI"
        ):
            candidates.add(target.id)

    return {
        name
        for name in candidates
        if assignments.get(name) == 1
    }


def _imported_module_paths(
    tree: ast.Module,
    *,
    available_paths: set[str],
) -> dict[str, str]:
    """Resolve direct package-module imports to selected Python files."""

    candidates: dict[str, set[str]] = {}
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
            local_name = alias.asname or alias.name
            module_name = f"{statement.module}.{alias.name}"
            candidate_path = module_name.replace(".", "/") + ".py"
            if candidate_path in available_paths:
                candidates.setdefault(local_name, set()).add(
                    candidate_path
                )

    return {
        name: next(iter(paths))
        for name, paths in candidates.items()
        if len(paths) == 1
    }


def _unique_apirouter_symbols(tree: ast.Module) -> set[str]:
    """Return uniquely assigned top-level APIRouter symbols."""

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
            and _leaf_name(value.func) == "APIRouter"
        ):
            candidates.add(target.id)

    return {
        name
        for name in candidates
        if assignments.get(name) == 1
    }


def _literal_dependencies(
    *,
    path: str,
    call: ast.Call,
) -> tuple[RouteDependencySummary, ...] | None:
    """Parse an explicit include_router dependencies list."""

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
            or _leaf_name(item.func) not in {"Depends", "Security"}
            or len(item.args) != 1
            or item.keywords
            or not isinstance(item.args[0], (ast.Name, ast.Attribute))
        ):
            return None

        target = item.args[0]
        found.append(
            RouteDependencySummary(
                full_name=ast.unparse(target),
                leaf_name=_leaf_name(target),
                source_kind="include_router",
                origin=_origin(path, item),
            )
        )

    return tuple(
        sorted(
            found,
            key=lambda item: (
                item.full_name,
                item.leaf_name or "",
            ),
        )
    )


def _top_level_include_router_calls(
    tree: ast.Module,
    *,
    app_symbols: set[str],
) -> list[ast.Call]:
    calls: list[ast.Call] = []
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
        ):
            continue
        calls.append(call)
    return calls


def infer_include_router_dependencies(
    *,
    parsed_trees: Mapping[str, ast.Module],
) -> IncludeRouterDependencyIndex:
    """Infer bounded cross-file include_router dependency attachments."""

    available_paths = set(parsed_trees)
    target_router_symbols = {
        path: _unique_apirouter_symbols(tree)
        for path, tree in parsed_trees.items()
    }

    collected: dict[
        tuple[str, str],
        list[RouteDependencySummary],
    ] = {}

    for source_path, tree in sorted(parsed_trees.items()):
        app_symbols = _unique_fastapi_app_symbols(tree)
        if not app_symbols:
            continue

        imported_modules = _imported_module_paths(
            tree,
            available_paths=available_paths,
        )
        for call in _top_level_include_router_calls(
            tree,
            app_symbols=app_symbols,
        ):
            if not call.args:
                continue
            router_expression = call.args[0]
            if (
                not isinstance(router_expression, ast.Attribute)
                or not isinstance(router_expression.value, ast.Name)
            ):
                continue

            module_alias = router_expression.value.id
            router_symbol = router_expression.attr
            target_path = imported_modules.get(module_alias)
            if target_path is None:
                continue
            if router_symbol not in target_router_symbols.get(
                target_path,
                set(),
            ):
                continue

            dependencies = _literal_dependencies(
                path=source_path,
                call=call,
            )
            if dependencies is None:
                continue

            collected.setdefault(
                (target_path, router_symbol),
                [],
            ).extend(dependencies)

    by_target: dict[
        str,
        dict[str, tuple[RouteDependencySummary, ...]],
    ] = {}
    for (target_path, router_symbol), values in sorted(
        collected.items()
    ):
        unique: dict[
            tuple[str, str | None, str, int | None, int | None],
            RouteDependencySummary,
        ] = {}
        for item in values:
            source_range = item.origin.source_range
            key = (
                item.full_name,
                item.leaf_name,
                item.origin.path,
                (
                    source_range.start_line
                    if source_range is not None
                    else None
                ),
                (
                    source_range.end_line
                    if source_range is not None
                    else None
                ),
            )
            unique[key] = item

        by_target.setdefault(target_path, {})[
            router_symbol
        ] = tuple(
            sorted(
                unique.values(),
                key=lambda item: (
                    item.full_name,
                    item.leaf_name or "",
                    item.origin.path,
                    (
                        item.origin.source_range.start_line
                        if item.origin.source_range is not None
                        and item.origin.source_range.start_line is not None
                        else 0
                    ),
                ),
            )
        )

    digests: dict[str, str] = {}
    for path in parsed_trees:
        payload = []
        for router_symbol, dependencies in sorted(
            by_target.get(path, {}).items()
        ):
            for item in dependencies:
                payload.append(
                    {
                        "router_symbol": router_symbol,
                        "full_name": item.full_name,
                        "leaf_name": item.leaf_name,
                        "source_kind": item.source_kind,
                        "origin": item.origin.model_dump(mode="json"),
                    }
                )
        digests[path] = content_digest(payload)

    return IncludeRouterDependencyIndex(
        dependencies_by_target=by_target,
        attachment_digests=digests,
    )
