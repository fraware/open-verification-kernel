import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/infrastructure_exposure/{name}").read_text(encoding="utf-8"))


def test_public_sensitive_resource_blocks() -> None:
    evidence = evaluate_infra_exposure(
        load_fixture("input_public_sensitive_resource.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["failure_mode"] == "sensitive_resource_publicly_exposed"


def test_private_sensitive_resource_allows() -> None:
    evidence = evaluate_infra_exposure(
        load_fixture("input_private_sensitive_resource.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []


def test_invalid_infra_input_requires_review() -> None:
    evidence = evaluate_infra_exposure(
        {"task": "missing resources"},
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.counterexamples[0]["failure_mode"] == "infrastructure_abstraction_invalid"
