"""Kubernetes object compiler for infrastructure IR.

Consumes Service, Ingress, Gateway API, NetworkPolicy, RBAC, ServiceAccount,
Secret refs, pod security, and admission metadata when present as objects.
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
                    if isinstance(_meta(obj).get("labels"), dict)
                    and str(key).startswith("pod-security.kubernetes.io/")
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
