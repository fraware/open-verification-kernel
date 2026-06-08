import json
from pathlib import Path

from ovk.adapters.z3 import evaluate_authorization_reachability
from ovk.adapters.z3.authorization import find_authorization_counterexamples


FIXTURE_DIR = Path("examples/auth_regression")


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_admin_bypass_produces_counterexample() -> None:
    data = load_fixture("input_admin_bypass.json")
    counterexamples = find_authorization_counterexamples(data)
    assert len(counterexamples) == 1
    assert counterexamples[0]["failure_mode"] == "admin_route_reachable_by_non_admin"
    assert counterexamples[0]["user_role"] == "user"


def test_admin_bypass_blocks_merge() -> None:
    data = load_fixture("input_admin_bypass.json")
    evidence = evaluate_authorization_reachability(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"


def test_admin_route_protected_allows_merge() -> None:
    data = load_fixture("input_admin_protected.json")
    evidence = evaluate_authorization_reachability(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []
