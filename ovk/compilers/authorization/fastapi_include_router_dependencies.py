"""Resolve cached FastAPI include_router dependency attachments.

Per-file route summaries retain only source-local syntax facts. This module joins
those cached facts across selected files to derive bounded include_router
inheritance without requiring cached source files to be reparsed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ovk.compilers.authorization.fastapi_route_summary import (
    RouteDependencySummary,
    RouteFileSummary,
    RouteSummaryIndex,
)
from ovk.core.bundle import content_digest


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


def _imported_module_paths(
    summary: RouteFileSummary,
    *,
    available_paths: set[str],
) -> dict[str, str]:
    candidates: dict[str, set[str]] = {}
    for item in summary.module_imports:
        candidate_path = item.module_name.replace(".", "/") + ".py"
        if candidate_path in available_paths:
            candidates.setdefault(item.local_name, set()).add(
                candidate_path
            )

    return {
        name: next(iter(paths))
        for name, paths in candidates.items()
        if len(paths) == 1
    }


def infer_include_router_dependencies(
    *,
    route_summary_index: RouteSummaryIndex,
) -> IncludeRouterDependencyIndex:
    """Join bounded include_router facts across cached per-file summaries."""

    summaries = route_summary_index.summaries
    available_paths = set(summaries)
    occurrences: dict[
        tuple[str, str],
        list[tuple[RouteDependencySummary, ...] | None],
    ] = {}

    for source_path, summary in sorted(summaries.items()):
        imported_modules = _imported_module_paths(
            summary,
            available_paths=available_paths,
        )
        for call in summary.include_router_calls:
            target_path = imported_modules.get(call.module_alias)
            if target_path is None:
                continue
            target_summary = summaries.get(target_path)
            if target_summary is None:
                continue
            if call.router_symbol not in target_summary.apirouter_symbols:
                continue

            occurrences.setdefault(
                (target_path, call.router_symbol),
                [],
            ).append(call.dependencies)

    by_target: dict[
        str,
        dict[str, tuple[RouteDependencySummary, ...]],
    ] = {}
    for (target_path, router_symbol), mounted in sorted(
        occurrences.items()
    ):
        # A router mounted more than once may be exposed under different
        # security contexts. The v1 theorem therefore declines all inherited
        # authorization semantics unless one static inclusion is established.
        if len(mounted) != 1 or mounted[0] is None:
            continue

        unique = {
            (item.full_name, item.leaf_name, item.factory_call): item
            for item in mounted[0]
        }
        by_target.setdefault(target_path, {})[
            router_symbol
        ] = tuple(
            sorted(
                unique.values(),
                key=lambda item: (
                    item.full_name,
                    item.leaf_name or "",
                    item.factory_call or "",
                    item.origin.path,
                ),
            )
        )

    digests: dict[str, str] = {}
    for path in summaries:
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
                        "factory_call": item.factory_call,
                        "origin": item.origin.model_dump(mode="json"),
                    }
                )
        digests[path] = content_digest(payload)

    return IncludeRouterDependencyIndex(
        dependencies_by_target=by_target,
        attachment_digests=digests,
    )
