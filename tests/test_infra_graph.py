from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.graph import graph_to_infra_input


def test_graph_reachable_sensitive_resource_blocks() -> None:
    graph = {
        "nodes": [
            {"id": "edge", "kind": "external"},
            {"id": "store", "kind": "storage", "sensitivity": "confidential"},
        ],
        "edges": [{"from": "edge", "to": "store"}],
    }
    evidence = evaluate_infra_exposure(graph_to_infra_input(graph), repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["resource_id"] == "store"


def test_graph_disconnected_sensitive_resource_allows() -> None:
    graph = {
        "nodes": [
            {"id": "edge", "kind": "external"},
            {"id": "store", "kind": "storage", "sensitivity": "confidential"},
        ],
        "edges": [],
    }
    evidence = evaluate_infra_exposure(graph_to_infra_input(graph), repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []


def test_empty_graph_becomes_invalid_infra_input() -> None:
    evidence = evaluate_infra_exposure(graph_to_infra_input({"nodes": [], "edges": []}), repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
