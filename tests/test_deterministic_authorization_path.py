import json
from pathlib import Path

from ovk.adapters.z3.deterministic_path import evaluate_deterministic_authorization_path


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/auth_regression/{name}").read_text(encoding="utf-8"))


def test_deterministic_path_blocks_bypass_without_z3_dependency() -> None:
    evidence = evaluate_deterministic_authorization_path(
        load_fixture("input_admin_bypass.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["query_polarity"] == "find_violation"


def test_deterministic_path_allows_protected_fixture_without_z3_dependency() -> None:
    evidence = evaluate_deterministic_authorization_path(
        load_fixture("input_admin_protected.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []


def test_deterministic_path_invalid_input_is_unknown() -> None:
    evidence = evaluate_deterministic_authorization_path(
        load_fixture("input_malformed_missing_routes.json"),
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
