"""Resolve source-proved FastAPI router-wrapper semantics across files.

Per-file route summaries stay context-independent. This module joins a unique
imported constructor binding in one file to a bounded APIRouter wrapper proof
in another selected source file.

The resulting owner fact is deliberately narrow: it establishes that route
registration preserves FastAPI APIRouter semantics for the summarized wrapper
shape. It does not infer authorization meaning, dependency effectiveness, or
resource interpretation equivalence beyond the already bounded route profile.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ovk.compilers.authorization.fastapi_route_summary import (
    RouteSummaryIndex,
    RouterWrapperClassSummary,
)
from ovk.core.bundle import content_digest


@dataclass(frozen=True)
class FastApiRouterWrapperIndex:
    """Cross-file source proof for FastAPI-equivalent route-owner symbols."""

    route_owner_symbols_by_path: dict[str, frozenset[str]] = field(
        default_factory=dict
    )
    attachment_digests: dict[str, str] = field(default_factory=dict)

    def owners_for(self, path: str) -> frozenset[str]:
        return self.route_owner_symbols_by_path.get(path, frozenset())

    def digest_for(self, path: str) -> str:
        return self.attachment_digests.get(path, content_digest([]))


def _module_path(
    module: str,
    *,
    available_paths: set[str],
) -> str | None:
    stem = module.replace(".", "/")
    candidates = [
        candidate
        for candidate in (f"{stem}.py", f"{stem}/__init__.py")
        if candidate in available_paths
    ]
    return candidates[0] if len(candidates) == 1 else None


def infer_fastapi_router_wrappers(
    *,
    route_summary_index: RouteSummaryIndex,
) -> FastApiRouterWrapperIndex:
    """Join imported constructors to bounded APIRouter wrapper proofs."""

    summaries = route_summary_index.summaries
    available_paths = set(summaries)
    wrappers: dict[
        tuple[str, str],
        RouterWrapperClassSummary,
    ] = {}

    for path, summary in sorted(summaries.items()):
        for wrapper in summary.router_wrapper_classes:
            wrappers[(path, wrapper.class_name)] = wrapper

    owners_by_path: dict[str, frozenset[str]] = {}
    digests: dict[str, str] = {}

    for path, summary in sorted(summaries.items()):
        owners: set[str] = set()
        evidence_payload: list[dict] = []

        for binding in summary.imported_constructor_bindings:
            target_path = _module_path(
                binding.import_module,
                available_paths=available_paths,
            )
            if target_path is None:
                continue
            wrapper = wrappers.get((target_path, binding.import_name))
            if wrapper is None:
                continue

            target_summary = summaries[target_path]
            owners.add(binding.symbol)
            evidence_payload.append(
                {
                    "route_path": path,
                    "owner_symbol": binding.symbol,
                    "constructor_local_name": binding.constructor_local_name,
                    "import_module": binding.import_module,
                    "import_name": binding.import_name,
                    "binding_origin": binding.origin.model_dump(mode="json"),
                    "wrapper_path": target_path,
                    "wrapper_source_digest": target_summary.source_digest,
                    "wrapper_class": wrapper.class_name,
                    "wrapper_proof_kind": wrapper.proof_kind,
                    "wrapper_origin": wrapper.origin.model_dump(mode="json"),
                }
            )

        if owners:
            owners_by_path[path] = frozenset(sorted(owners))
        digests[path] = content_digest(
            sorted(
                evidence_payload,
                key=lambda item: (
                    item["owner_symbol"],
                    item["wrapper_path"],
                    item["wrapper_class"],
                ),
            )
        )

    return FastApiRouterWrapperIndex(
        route_owner_symbols_by_path=owners_by_path,
        attachment_digests=digests,
    )
