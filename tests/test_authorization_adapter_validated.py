import json
from pathlib import Path

from ovk.adapters.z3.authorization import evaluate_authorization_reachability, find_authorization_counterexamples


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/auth_regression/{name}").read_text(encoding="utf-8"))


def test_legacy_counterexample_helper_uses_obligation_metadata() -> None:
    counterexamples = find_authorization_counterexamples(load_fixture("input_admin_bypass.json"))
    assert counterexamples[0]["failure_mode"] == "admin_route_reachable_by_non_admin"
    assert counterexamples[0]["query_polarity"] == "find_violation"
    assert "obligation_id" in counterexamples[0]


def test_stable_authorization_adapter_rejects_malformed_input_as_unknown() -> None:
    evidence = evaluate_authorization_reachability(
        load_fixture("input_malformed_missing_routes.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.counterexamples[0]["failure_mode"] == "authorization_abstraction_invalid"


def test_stable_authorization_adapter_preserves_pull_request_subject() -> None:
    evidence = evaluate_authorization_reachability(
        load_fixture("input_admin_protected.json"),
        repo="example/repo",
        head_sha="abc",
        pull_request=17,
    )
    assert evidence.subject["pull_request"] == 17
