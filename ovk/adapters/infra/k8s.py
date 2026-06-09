"""Kubernetes-style normalization for infrastructure exposure checks."""

from __future__ import annotations

from typing import Any


SENSITIVITY_ANNOTATIONS = (
    "ovk.io/sensitivity",
    "data.sensitivity",
    "data_classification",
    "classification",
)


def _metadata(resource: dict[str, Any]) -> dict[str, Any]:
    metadata = resource.get("metadata", {})
    return metadata if isinstance(metadata, dict) else {}


def _annotations(resource: dict[str, Any]) -> dict[str, Any]:
    annotations = _metadata(resource).get("annotations", {})
    return annotations if isinstance(annotations, dict) else {}


def _name(resource: dict[str, Any], index: int) -> str:
    metadata = _metadata(resource)
    name = metadata.get("name")
    namespace = metadata.get("namespace", "default")
    if isinstance(name, str) and name:
        return f"{namespace}/{name}"
    return f"default/resource-{index}"


def _sensitivity(resource: dict[str, Any]) -> str:
    annotations = _annotations(resource)
    for key in SENSITIVITY_ANNOTATIONS:
        value = annotations.get(key)
        if isinstance(value, str) and value in {"public", "internal", "confidential", "restricted"}:
            return value
    return "internal"


def _public_exposure(resource: dict[str, Any]) -> bool:
    spec = resource.get("spec", {})
    if not isinstance(spec, dict):
        return False
    service_type = spec.get("type")
    if service_type in {"LoadBalancer", "NodePort"}:
        return True
    annotations = _annotations(resource)
    if annotations.get("ovk.io/public-exposure") == "true":
        return True
    return False


def _exposure_paths(resource: dict[str, Any]) -> list[str]:
    spec = resource.get("spec", {})
    paths: list[str] = []
    if isinstance(spec, dict) and isinstance(spec.get("type"), str):
        paths.append(f"service:{spec['type']}")
    if _annotations(resource).get("ovk.io/public-exposure") == "true":
        paths.append("annotation:ovk.io/public-exposure")
    return paths


def k8s_resources_to_infra_input(data: dict[str, Any]) -> dict[str, Any]:
    """Convert a small Kubernetes-style manifest bundle into OVK infra input."""
    items = data.get("items")
    if not isinstance(items, list):
        items = [data]

    resources: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", "Unknown"))
        if kind != "Service":
            continue
        resource_id = _name(item, index)
        resources.append(
            {
                "resource_id": resource_id,
                "resource_type": "kubernetes_service",
                "sensitivity": _sensitivity(item),
                "public_exposure": _public_exposure(item),
                "exposure_paths": _exposure_paths(item),
            }
        )
    return {
        "author_type": data.get("author_type", "unknown"),
        "agent": data.get("agent", "unknown"),
        "task": data.get("task", "kubernetes_normalization"),
        "resources": resources,
    }
