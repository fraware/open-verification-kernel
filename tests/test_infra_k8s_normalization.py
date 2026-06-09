from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.k8s import k8s_resources_to_infra_input


def test_sensitive_public_service_blocks() -> None:
    data = {
        "kind": "Service",
        "metadata": {
            "namespace": "prod",
            "name": "data-api",
            "annotations": {"ovk.io/sensitivity": "confidential"},
        },
        "spec": {"type": "LoadBalancer"},
    }
    infra_input = k8s_resources_to_infra_input(data)
    evidence = evaluate_infra_exposure(infra_input, repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "block"


def test_internal_public_service_allows() -> None:
    data = {
        "kind": "Service",
        "metadata": {
            "namespace": "prod",
            "name": "frontend",
            "annotations": {"ovk.io/sensitivity": "internal"},
        },
        "spec": {"type": "LoadBalancer"},
    }
    infra_input = k8s_resources_to_infra_input(data)
    evidence = evaluate_infra_exposure(infra_input, repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "allow"
