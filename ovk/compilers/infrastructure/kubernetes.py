"""Kubernetes object compiler for infrastructure IR.

Consumes Service, Ingress, Gateway API, NetworkPolicy, RBAC, ServiceAccount,
Secret refs, pod security, and admission metadata when present as objects.

Profile ``infrastructure.kubernetes.controller_reachability_v1`` adds
controller-aware edges from public Services to matching Deployment/StatefulSet/
DaemonSet workloads via label selectors.
"""

from __future__ import annotations

from typing import Any

from ovk.compilers.infrastructure.exposure_graph import (
    apply_concrete_exposure,
    build_edges,
    concrete_public_paths,
)
from ovk.compilers.infrastructure.ir import ExposureEdge, InfraResourceIR, InfrastructureIR
from ovk.compilers.infrastructure.reachability import evaluate_eligibility
from ovk.compilers.infrastructure.sensitivity import normalize_sensitivity

_SOURCE_PROFILE_ID = "infrastructure.kubernetes.controller_reachability_v1"
_CONTROLLER_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"})


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    meta = obj.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _name(obj: dict[str, Any], index: int) -> str:
    meta = _meta(obj)
    name = meta.get("name") or f"resource-{index}"
    namespace = meta.get("namespace") or "default"
    return f"{namespace}/{name}"


def _annotations(obj: dict[str, Any]) -> dict[str, Any]:
    annotations = _meta(obj).get("annotations")
    return annotations if isinstance(annotations, dict) else {}


def _sensitivity(obj: dict[str, Any]) -> str:
    annotations = _annotations(obj)
    for key in ("ovk.io/sensitivity", "data.sensitivity", "classification"):
        value = annotations.get(key)
        if isinstance(value, str):
            return normalize_sensitivity(value)
    return "internal"


def compile_kubernetes_objects(objects: list[dict[str, Any]] | dict[str, Any]) -> InfrastructureIR:
    """Compile Kubernetes objects (list or {"items": [...]}) into IR."""
    if isinstance(objects, dict):
        items = objects.get("items")
        objects_list = items if isinstance(items, list) else [objects]
    else:
        objects_list = objects

    resources: list[InfraResourceIR] = []
    edges: list[ExposureEdge] = []
    unsupported: list[str] = []
    warnings: list[str] = []

    for index, obj in enumerate(objects_list):
        if not isinstance(obj, dict):
            unsupported.append(f"objects[{index}]_not_object")
            continue
        kind = str(obj.get("kind") or "Unknown")
        resource_id = _name(obj, index)
        sensitivity = _sensitivity(obj)
        spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
        paths: list[str] = []
        public = False
        resource_kind = "kubernetes"
        attributes: dict[str, Any] = {"apiVersion": obj.get("apiVersion"), "kind": kind}

        if kind == "Service":
            resource_kind = "service"
            svc_type = spec.get("type")
            if svc_type in {"LoadBalancer", "NodePort"}:
                public = True
                paths = [str(svc_type)]
        elif kind == "Ingress":
            resource_kind = "ingress"
            public = True
            paths = ["public_ingress"]
            backend = None
            rules = spec.get("rules") if isinstance(spec.get("rules"), list) else []
            for rule in rules:
                http = rule.get("http") if isinstance(rule, dict) else None
                http_paths = http.get("paths") if isinstance(http, dict) else None
                if isinstance(http_paths, list) and http_paths:
                    svc = http_paths[0].get("backend", {}).get("service", {})
                    if isinstance(svc, dict) and svc.get("name"):
                        backend = f"{_meta(obj).get('namespace', 'default')}/{svc['name']}"
                        break
            if backend:
                edges.append(
                    ExposureEdge(source=resource_id, target=backend, kind="ingress_backend", evidence="Ingress")
                )
        elif kind in {"Gateway", "HTTPRoute"}:
            resource_kind = "gateway"
            public = kind == "Gateway"
            paths = ["gateway_api"] if public else []
        elif kind == "NetworkPolicy":
            resource_kind = "network_policy"
            attributes["policy_types"] = spec.get("policyTypes")
        elif kind in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}:
            resource_kind = "rbac"
            attributes["rules"] = obj.get("rules") or spec.get("roles")
        elif kind == "ServiceAccount":
            resource_kind = "service_account"
            secrets = obj.get("secrets") if isinstance(obj.get("secrets"), list) else []
            attributes["secret_refs"] = secrets
            if secrets:
                resource_kind = "secret_ref"
        elif kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet"}:
            resource_kind = "pod_security"
            template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
            pod_spec = template.get("spec") if isinstance(template, dict) else spec
            if isinstance(pod_spec, dict):
                attributes["serviceAccountName"] = pod_spec.get("serviceAccountName")
                attributes["securityContext"] = pod_spec.get("securityContext")
                # Admission / PSA metadata.
                attributes["pod_security_labels"] = {
                    key: value
                    for key, value in _meta(obj).get("labels", {}).items()
                    if isinstance(_meta(obj).get("labels"), dict) and str(key).startswith("pod-security.kubernetes.io/")
                }
        else:
            unsupported.append(f"{resource_id}:unsupported_kind:{kind}")
            continue

        resources.append(
            InfraResourceIR(
                resource_id=resource_id,
                resource_type=kind,
                kind=resource_kind,  # type: ignore[arg-type]
                sensitivity=sensitivity,
                public_exposure=public,
                exposure_paths=paths,
                attributes=attributes,
            )
        )

    controller_edges = _controller_reachability_edges(objects_list, resources)
    if controller_edges:
        edges.extend(controller_edges)
        warnings.append(f"compiled_with_source_profile:{_SOURCE_PROFILE_ID}")

    all_edges = build_edges(resources, edges)
    paths = concrete_public_paths(resources, all_edges)
    resources = apply_concrete_exposure(resources, paths)
    ir = InfrastructureIR(
        source_kind="kubernetes",
        resources=resources,
        edges=all_edges,
        public_paths=paths,
        unsupported_constructs=sorted(set(unsupported)),
        warnings=warnings,
    )
    return evaluate_eligibility(ir)


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    labels = _meta(obj).get("labels")
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items()}


def _selector_match(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    if not isinstance(selector, dict) or not selector:
        return False
    match_labels = selector.get("matchLabels")
    if isinstance(match_labels, dict):
        return all(labels.get(str(key)) == str(value) for key, value in match_labels.items())
    # Service selectors are flat maps.
    return all(labels.get(str(key)) == str(value) for key, value in selector.items())


def _controller_reachability_edges(
    objects: list[Any],
    resources: list[InfraResourceIR],
) -> list[ExposureEdge]:
    """Link public Services to controllers whose pod template labels match."""
    resource_ids = {item.resource_id for item in resources}
    services: list[tuple[str, dict[str, Any]]] = []
    controllers: list[tuple[str, dict[str, Any]]] = []
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            continue
        kind = str(obj.get("kind") or "")
        resource_id = _name(obj, index)
        spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
        if kind == "Service":
            services.append((resource_id, spec if isinstance(spec, dict) else {}))
        elif kind in _CONTROLLER_KINDS:
            controllers.append((resource_id, obj))

    edges: list[ExposureEdge] = []
    for service_id, service_spec in services:
        if service_id not in resource_ids:
            continue
        selector = service_spec.get("selector")
        if not isinstance(selector, dict):
            continue
        for controller_id, controller in controllers:
            template = controller.get("spec", {}).get("template") if isinstance(controller.get("spec"), dict) else None
            labels = _labels(template) if isinstance(template, dict) else {}
            if not _selector_match(selector, labels):
                continue
            # Ensure controller appears as a resource so paths can terminate.
            if controller_id not in resource_ids:
                resources.append(
                    InfraResourceIR(
                        resource_id=controller_id,
                        resource_type=str(controller.get("kind") or "Controller"),
                        kind="pod_security",
                        sensitivity=_sensitivity(controller),
                        attributes={
                            "source_profile": _SOURCE_PROFILE_ID,
                            "controller_kind": controller.get("kind"),
                        },
                    )
                )
                resource_ids.add(controller_id)
            edges.append(
                ExposureEdge(
                    source=service_id,
                    target=controller_id,
                    kind="service_selector",
                    evidence=f"compiled_with_source_profile:{_SOURCE_PROFILE_ID}",
                )
            )
    return edges
