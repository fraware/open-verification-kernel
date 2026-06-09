import json
from pathlib import Path

from ovk.adapters.z3.evidence import authorization_result_to_evidence
from ovk.adapters.z3.obligation import build_authorization_obligation


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/auth_regression/{name}").read_text(encoding="utf-8"))


def test_authorization_fail_result_maps_to_blocking_evidence() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    evidence = authorization_result_to_evidence(
        {
            "status": "fail",
            "reason": "violation model found",
            "models": [
                {
                    "route": "/admin/export",
                    "user_role": "user",
                    "path": ["route_group_added"],
                    "model": "model",
                    "obligation_id": obligation.obligation_id,
                    "query_polarity": obligation.query_polarity,
                }
            ],
        },
        obligation,
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["query_polarity"] == "find_violation"
    assert any(item["kind"] == "regression_unit_test" for item in evidence.generated_artifacts)


def test_authorization_pass_result_maps_to_allow() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_protected.json"))
    evidence = authorization_result_to_evidence(
        {"status": "pass", "reason": "no violation model found", "models": []},
        obligation,
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []


def test_authorization_unknown_result_maps_to_human_review() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    evidence = authorization_result_to_evidence(
        {"status": "unknown", "reason": "z3-solver is not installed", "models": []},
        obligation,
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.counterexamples == []
