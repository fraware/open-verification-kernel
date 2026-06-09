import json
from pathlib import Path

from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.adapters.z3.validation import validate_authorization_input


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/auth_regression/{name}").read_text(encoding="utf-8"))


def test_missing_routes_is_validation_error() -> None:
    issues = validate_authorization_input(load_fixture("input_malformed_missing_routes.json"))
    assert len(issues) == 1
    assert issues[0].path == "routes"


def test_bad_witness_is_validation_error() -> None:
    issues = validate_authorization_input(load_fixture("input_malformed_bad_witness.json"))
    issue_paths = {issue.path for issue in issues}
    assert "routes[0].reachable_after[0].role" in issue_paths
    assert "routes[0].reachable_after[0].via" in issue_paths


def test_validated_path_malformed_input_requires_human_review() -> None:
    evidence = evaluate_validated_authorization_path(
        load_fixture("input_malformed_missing_routes.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.counterexamples[0]["failure_mode"] == "authorization_abstraction_invalid"


def test_validated_path_valid_input_does_not_emit_validation_failure() -> None:
    evidence = evaluate_validated_authorization_path(
        load_fixture("input_admin_protected.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert all(
        item.get("failure_mode") != "authorization_abstraction_invalid"
        for item in evidence.counterexamples
    )
