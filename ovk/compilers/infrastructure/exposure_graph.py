"""Exposure graph construction and concrete public-path requirements."""

from __future__ import annotations

from collections import defaultdict, deque

from ovk.compilers.infrastructure.ir import ExposureEdge, ExposurePath, InfraResourceIR


PUBLIC_ENTRY = "internet"
PUBLIC_PATH_HINTS = frozenset(
    {
        "internet_gateway",
        "internet_accessible",
        "LoadBalancer",
        "NodePort",
        "public_ingress",
        "gateway_api",
        "public_policy",
        "public_bucket_policy",
    }
)


def build_edges(resources: list[InfraResourceIR], declared: list[ExposureEdge] | None = None) -> list[ExposureEdge]:
    """Build exposure edges from explicit declarations and resource hints."""
    edges = list(declared or [])
    for resource in resources:
        concrete_labels = [
            label
            for label in resource.exposure_paths
            if label in PUBLIC_PATH_HINTS or label.startswith("acl:") or "->" in label
        ]
        for path_label in concrete_labels:
            edges.append(
                ExposureEdge(
                    source=PUBLIC_ENTRY,
                    target=resource.resource_id,
                    kind=path_label,
                    evidence=path_label,
                )
            )
        if resource.public_exposure and not any(
            edge.source == PUBLIC_ENTRY and edge.target == resource.resource_id for edge in edges
        ):
            # Public without a concrete path is recorded as a warning edge kind.
            edges.append(
                ExposureEdge(
                    source=PUBLIC_ENTRY,
                    target=resource.resource_id,
                    kind="declared_public_without_path",
                    evidence="public_exposure=true",
                )
            )
    return sorted(edges, key=lambda item: (item.source, item.target, item.kind))


def concrete_public_paths(
    resources: list[InfraResourceIR],
    edges: list[ExposureEdge],
) -> list[ExposurePath]:
    """Return concrete paths from the public entry to each reachable resource.

    A resource is only considered publicly exposed for strict eligibility when
    at least one concrete path (length >= 1 edge) exists from ``internet``.
    """
    adjacency: dict[str, list[ExposureEdge]] = defaultdict(list)
    for edge in edges:
        if edge.kind == "declared_public_without_path":
            continue
        adjacency[edge.source].append(edge)

    paths: list[ExposurePath] = []
    resource_ids = {item.resource_id for item in resources}
    queue: deque[tuple[str, list[str], list[ExposureEdge]]] = deque([(PUBLIC_ENTRY, [PUBLIC_ENTRY], [])])
    seen: set[tuple[str, str]] = set()
    while queue:
        node, nodes, edge_path = queue.popleft()
        for edge in adjacency.get(node, []):
            marker = (edge.source, edge.target)
            if marker in seen:
                continue
            seen.add(marker)
            next_nodes = nodes + [edge.target]
            next_edges = edge_path + [edge]
            if edge.target in resource_ids and len(next_nodes) >= 2:
                paths.append(ExposurePath(nodes=next_nodes, edges=next_edges))
            queue.append((edge.target, next_nodes, next_edges))
    return sorted(paths, key=lambda item: (item.nodes[-1] if item.nodes else "", len(item.nodes)))


def apply_concrete_exposure(resources: list[InfraResourceIR], paths: list[ExposurePath]) -> list[InfraResourceIR]:
    """Mark resources publicly exposed only when a concrete path exists."""
    exposed_ids = {path.nodes[-1] for path in paths if path.is_concrete}
    updated: list[InfraResourceIR] = []
    for resource in resources:
        path_labels = [
            " -> ".join(path.nodes)
            for path in paths
            if path.is_concrete and path.nodes[-1] == resource.resource_id
        ]
        updated.append(
            resource.model_copy(
                update={
                    "public_exposure": resource.resource_id in exposed_ids,
                    "exposure_paths": path_labels or list(resource.exposure_paths),
                }
            )
        )
    return updated
