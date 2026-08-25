"""Kubernetes object compiler for infrastructure IR.

Consumes Service, Ingress, Gateway API, NetworkPolicy, RBAC, ServiceAccount,
Secret refs, pod security, and admission metadata when present as objects.

Profile ``infrastructure.kubernetes.controller_reachability_v1`` adds
controller-aware edges from public Services to matching Deployment/StatefulSet/
DaemonSet workloads via label selectors. Service selectors are namespace-scoped:
a Service must never acquire a controller edge solely because matching pod labels
exist in another namespace.
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


def _namespace(obj: dict[str, Any]) -> str:
    return str(_meta(obj).get("namespace") or "default")


def _name(obj: dict[str, Any], index: int) -> str:
    meta = _meta(obj)
    name = meta.get("name") or f"resource-{index}"
    return f"{_namespace(obj)}/{name}"


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
        attributes: dict[str, Any] = {
            "apiVersion": obj.get("apiVersion"),
            "kind": kind,
            "namespace": _namespace(obj),
        }

        if kind == "Service":
            resource_kind = "service"
            svc_type = spec.get("type")
            if svc_type in {"LoadBalancer", "NodePort"}:
                public = True
                paths = [str(svc_type)]
        elif kind == "Ingress":
            resource_kind = "ingress"
            # Ingress publicness only with trusted class/address material.
            ingress_class = spec.get("ingressClassName") or _annotations(obj).get("kubernetes.io/ingress.class")
            if ingress_class:
                public = True
                paths = ["public_ingress"]
                attributes["ingressClassName"] = ingress_class
            else:
                unsupported.append(f"{resource_id}:ingress_missing_trusted_class")
                public = False
                paths = []
            backend = None
            rules = spec.get("rules") if isinstance(spec.get("rules"), list) else []
            for rule in rules:
                http = rule.get("http") if isinstance(rule, dict) else None
                http_paths = http.get("paths") if isinstance(http, dict) else None
                if isinstance(http_paths, list) and http_paths:
                    svc = http_paths[0].get("backend", {}).get("service", {})
                    if isinstance(svc, dict) and svc.get("name"):
                        backend = f"{_namespace(obj)}/{svc['name']}"
                        break
            if backend:
                edges.append(
                    ExposureEdge(source=resource_id, target=backend, kind="ingress_backend", evidence="Ingress")
                )
        elif kind in {"Gateway", "HTTPRoute", "ReferenceGrant", "GatewayClass"}:
            resource_kind = "gateway"
            if kind == "Gateway":
                # Publicness requires trusted address/class material; otherwise review.
                addresses = spec.get("addresses") if isinstance(spec.get("addresses"), list) else []
                gateway_class = spec.get("gatewayClassName")
                if addresses or gateway_class:
                    public = True
                    paths = ["gateway_api"]
                    attributes["gatewayClassName"] = gateway_class
                    attributes["addresses"] = addresses
                else:
                    unsupported.append(f"{resource_id}:gateway_missing_trusted_class_or_address")
                listeners = spec.get("listeners") if isinstance(spec.get("listeners"), list) else []
                attributes["listeners"] = [
                    {
                        "name": item.get("name"),
                        "port": item.get("port"),
                        "protocol": item.get("protocol"),
                    }
                    for item in listeners
                    if isinstance(item, dict)
                ]
            elif kind == "HTTPRoute":
                parent_refs = spec.get("parentRefs") if isinstance(spec.get("parentRefs"), list) else []
                rules = spec.get("rules") if isinstance(spec.get("rules"), list) else []
                for pref in parent_refs:
                    if not isinstance(pref, dict):
                        continue
                    parent_ns = str(pref.get("namespace") or _namespace(obj))
                    parent_name = pref.get("name")
                    if parent_name:
                        edges.append(
                            ExposureEdge(
                                source=f"{parent_ns}/{parent_name}",
                                target=resource_id,
                                kind="gateway_parent_ref",
                                evidence="HTTPRoute.parentRefs",
                            )
                        )
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    backend_refs = rule.get("backendRefs") if isinstance(rule.get("backendRefs"), list) else []
                    for bref in backend_refs:
                        if not isinstance(bref, dict) or not bref.get("name"):
                            continue
                        backend_ns = str(bref.get("namespace") or _namespace(obj))
                        if backend_ns != _namespace(obj):
                            # Cross-namespace backend requires ReferenceGrant; mark pending.
                            attributes.setdefault("pending_reference_grants", []).append(
                                f"{backend_ns}/{bref['name']}"
                            )
                        edges.append(
                            ExposureEdge(
                                source=resource_id,
                                target=f"{backend_ns}/{bref['name']}",
                                kind="httproute_backend_ref",
                                evidence="HTTPRoute.backendRefs",
                            )
                        )
            elif kind == "ReferenceGrant":
                attributes["from"] = spec.get("from")
                attributes["to"] = spec.get("to")
            elif kind == "GatewayClass":
                attributes["controllerName"] = spec.get("controllerName")
        elif kind == "NetworkPolicy":
            resource_kind = "network_policy"
            attributes["policy_types"] = spec.get("policyTypes")
            attributes["pod_selector"] = spec.get("podSelector")
            attributes["ingress"] = spec.get("ingress")
            attributes["egress"] = spec.get("egress")
            # Default-deny when policyTypes present with empty ingress.
            policy_types = spec.get("policyTypes") if isinstance(spec.get("policyTypes"), list) else []
            ingress = spec.get("ingress")
            if "Ingress" in policy_types and (ingress is None or ingress == []):
                attributes["default_deny_ingress"] = True
            # ipBlock except handling
            if isinstance(ingress, list):
                for rule in ingress:
                    if not isinstance(rule, dict):
                        continue
                    for peer in rule.get("from") or []:
                        if not isinstance(peer, dict):
                            continue
                        ip_block = peer.get("ipBlock")
                        if isinstance(ip_block, dict) and ip_block.get("except"):
                            attributes.setdefault("ipblock_except", []).append(ip_block)
        elif kind in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}:
            resource_kind = "rbac"
            attributes["rules"] = obj.get("rules") or spec.get("roles")
            attributes["rbac_graph"] = "separate_from_network_exposure"
            subjects = obj.get("subjects") if isinstance(obj.get("subjects"), list) else []
            role_ref = obj.get("roleRef") if isinstance(obj.get("roleRef"), dict) else {}
            attributes["subjects"] = subjects
            attributes["roleRef"] = role_ref
            for subject in subjects:
                if not isinstance(subject, dict):
                    continue
                if subject.get("kind") == "ServiceAccount" and subject.get("name"):
                    sa_ns = str(subject.get("namespace") or _namespace(obj))
                    edges.append(
                        ExposureEdge(
                            source=resource_id,
                            target=f"{sa_ns}/{subject['name']}",
                            kind="rbac_binding",
                            evidence=kind,
                        )
                    )
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
                attributes["pod_security_labels"] = {
                    key: value
                    for key, value in _meta(obj).get("labels", {}).items()
                    if isinstance(_meta(obj).get("labels"), dict) and str(key).startswith("pod-security.kubernetes.io/")
                }
                # Secret env/volume flow to workloads.
                secret_refs: list[str] = []
                for container in list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or []):
                    if not isinstance(container, dict):
                        continue
                    for env in container.get("env") or []:
                        if not isinstance(env, dict):
                            continue
                        value_from = env.get("valueFrom") if isinstance(env.get("valueFrom"), dict) else {}
                        secret_key = value_from.get("secretKeyRef")
                        if isinstance(secret_key, dict) and secret_key.get("name"):
                            secret_refs.append(str(secret_key["name"]))
                    for env_from in container.get("envFrom") or []:
                        if isinstance(env_from, dict) and isinstance(env_from.get("secretRef"), dict):
                            name = env_from["secretRef"].get("name")
                            if name:
                                secret_refs.append(str(name))
                for volume in pod_spec.get("volumes") or []:
                    if isinstance(volume, dict) and isinstance(volume.get("secret"), dict):
                        name = volume["secret"].get("secretName")
                        if name:
                            secret_refs.append(str(name))
                if secret_refs:
                    attributes["secret_refs"] = sorted(set(secret_refs))
                    for secret_name in sorted(set(secret_refs)):
                        edges.append(
                            ExposureEdge(
                                source=f"{_namespace(obj)}/{secret_name}",
                                target=resource_id,
                                kind="secret_to_workload",
                                evidence="pod_env_or_volume",
                            )
                        )
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
    return all(labels.get(str(key)) == str(value) for key, value in selector.items())


def _controller_reachability_edges(
    objects: list[Any],
    resources: list[InfraResourceIR],
) -> list[ExposureEdge]:
    """Link Services only to same-namespace controllers with matching pod labels."""
    resource_ids = {item.resource_id for item in resources}
    services: list[tuple[str, str, dict[str, Any]]] = []
    controllers: list[tuple[str, str, dict[str, Any]]] = []
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            continue
        kind = str(obj.get("kind") or "")
        resource_id = _name(obj, index)
        namespace = _namespace(obj)
        spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
        if kind == "Service":
            services.append((resource_id, namespace, spec if isinstance(spec, dict) else {}))
        elif kind in _CONTROLLER_KINDS:
            controllers.append((resource_id, namespace, obj))

    edges: list[ExposureEdge] = []
    for service_id, service_namespace, service_spec in services:
        if service_id not in resource_ids:
            continue
        selector = service_spec.get("selector")
        if not isinstance(selector, dict):
            continue
        for controller_id, controller_namespace, controller in controllers:
            # Kubernetes Service selectors are namespace-scoped. A matching label
            # set in another namespace is not a reachable backend for this Service.
            if controller_namespace != service_namespace:
                continue
            template = controller.get("spec", {}).get("template") if isinstance(controller.get("spec"), dict) else None
            labels = _labels(template) if isinstance(template, dict) else {}
            if not _selector_match(selector, labels):
                continue
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
                            "namespace": controller_namespace,
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
