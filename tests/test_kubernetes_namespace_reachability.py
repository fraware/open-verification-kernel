"""Kubernetes controller-reachability namespace semantics."""

from ovk.compilers.infrastructure.kubernetes import compile_kubernetes_objects


def _service(namespace: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "api", "namespace": namespace},
        "spec": {
            "type": "LoadBalancer",
            "selector": {"app": "api"},
        },
    }


def _deployment(namespace: str, name: str = "workload") -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {"ovk.io/sensitivity": "confidential"},
        },
        "spec": {
            "selector": {"matchLabels": {"app": "api"}},
            "template": {
                "metadata": {"labels": {"app": "api"}},
                "spec": {"containers": [{"name": "api", "image": "example/api:1"}]},
            },
        },
    }


def _selector_edges(ir) -> list:
    return [edge for edge in ir.edges if edge.kind == "service_selector"]


def test_matching_labels_in_different_namespace_do_not_create_reachability() -> None:
    ir = compile_kubernetes_objects([
        _service("public"),
        _deployment("private"),
    ])
    assert _selector_edges(ir) == []


def test_matching_labels_in_same_namespace_create_reachability() -> None:
    ir = compile_kubernetes_objects([
        _service("public"),
        _deployment("public"),
    ])
    edges = _selector_edges(ir)
    assert len(edges) == 1
    assert edges[0].source == "public/api"
    assert edges[0].target == "public/workload"


def test_same_label_in_two_namespaces_only_links_same_namespace_controller() -> None:
    ir = compile_kubernetes_objects([
        _service("public"),
        _deployment("public", "public-workload"),
        _deployment("private", "private-workload"),
    ])
    edges = _selector_edges(ir)
    assert len(edges) == 1
    assert edges[0].source == "public/api"
    assert edges[0].target == "public/public-workload"
