"""Graph-style normalization for infrastructure exposure checks."""

from __future__ import annotations

from collections import deque
from typing import Any


VALID_SENSITIVITY = {"public", "internal", "confidential", "restricted"}


def _node_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes = data.get("nodes", [])
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(nodes, list):
        return result
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        if isinstance(node_id, str) and node_id:
            result[node_id] = node
    return result


def _adjacency(data: dict[str, Any]) -> dict[str, list[str]]:
    edges = data.get("edges", [])
    graph: dict[str, list[str]] = {}
    if not isinstance(edges, list):
        return graph
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = edge.get("from")
        target = edge.get("to")
        if isinstance(source, str) and isinstance(target, str):
            graph.setdefault(source, []).append(target)
    return graph


def _entrypoints(nodes: dict[str, dict[str, Any]]) -> list[str]:
    return [
        node_id
        for node_id, node in nodes.items()
        if node.get("external") is True or node.get("kind") == "external"
    ]


def _reachable_from_entrypoints(nodes: dict[str, dict[str, Any]], graph: dict[str, list[str]]) -> dict[str, list[str]]:
    paths: dict[str, list[str]] = {}
    queue: deque[tuple[str, list[str]]] = deque()
    for entrypoint in _entrypoints(nodes):
        queue.append((entrypoint, [entrypoint]))
        paths[entrypoint] = [entrypoint]

    while queue:
        current, path = queue.popleft()
        for target in graph.get(current, []):
            if target in paths:
                continue
            next_path = path + [target]
            paths[target] = next_path
            queue.append((target, next_path))
    return paths


def _sensitivity(node: dict[str, Any]) -> str:
    value = node.get("sensitivity", "internal")
    if isinstance(value, str) and value in VALID_SENSITIVITY:
        return value
    return "internal"


def graph_to_infra_input(data: dict[str, Any]) -> dict[str, Any]:
    """Convert a graph-style infrastructure abstraction into OVK infra input."""
    nodes = _node_map(data)
    graph = _adjacency(data)
    reachable = _reachable_from_entrypoints(nodes, graph)
    resources: list[dict[str, Any]] = []

    for node_id, node in nodes.items():
        if node.get("kind") == "external" or node.get("external") is True:
            continue
        resource_type = str(node.get("resource_type", node.get("kind", "resource")))
        resources.append(
            {
                "resource_id": node_id,
                "resource_type": resource_type,
                "sensitivity": _sensitivity(node),
                "public_exposure": node_id in reachable,
                "exposure_paths": reachable.get(node_id, []),
            }
        )

    return {
        "author_type": data.get("author_type", "unknown"),
        "agent": data.get("agent", "unknown"),
        "task": data.get("task", "graph_normalization"),
        "resources": resources,
    }
