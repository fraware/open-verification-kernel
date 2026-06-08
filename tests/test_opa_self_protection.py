import json
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.adapters.opa.self_protection import find_self_protection_violations


FIXTURE_DIR = Path("examples/no_agent_self_approval")


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_gate_removed_produces_violation() -> None:
    data = load_fixture("input_gate_removed.json")
    violations = find_self_protection_violations(data)
    assert len(violations) == 1
    assert violations[0].failure_mode == "required_check_removed"


def test_gate_removed_blocks_merge() -> None:
    data = load_fixture("input_gate_removed.json")
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["failure_mode"] == "required_check_removed"


def test_gate_preserved_allows_merge() -> None:
    data = load_fixture("input_gate_preserved.json")
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []


def test_human_authored_change_does_not_trigger_agent_self_protection() -> None:
    data = load_fixture("input_gate_removed.json")
    data["actor"]["type"] = "human"
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
