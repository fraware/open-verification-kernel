import json
from pathlib import Path

import pytest

from ovk.adapters.z3.executor import run_authorization_obligation_with_z3
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.result import normalize_z3_authorization_result, recommendation_from_z3_status


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/auth_regression/{name}").read_text(encoding="utf-8"))


def test_recommendation_from_z3_status() -> None:
    assert recommendation_from_z3_status("fail") == "block"
    assert recommendation_from_z3_status("unknown") == "require_human_review"
    assert recommendation_from_z3_status("error") == "require_human_review"
    assert recommendation_from_z3_status("pass") == "allow"


def test_normalize_z3_fail_result_to_counterexample() -> None:
    normalized = normalize_z3_authorization_result(
        {
            "status": "fail",
            "reason": "violation model found",
            "models": [
                {
                    "route": "/admin/export",
                    "user_role": "user",
                    "path": ["route_group_added"],
                    "model": "model",
                    "obligation_id": "obl-auth-admin-route-reachability",
                    "query_polarity": "find_violation",
                }
            ],
        }
    )
    assert normalized["status"] == "fail"
    assert normalized["counterexamples"][0]["query_polarity"] == "find_violation"


def test_normalize_z3_unknown_preserves_unknown() -> None:
    normalized = normalize_z3_authorization_result(
        {"status": "unknown", "reason": "z3-solver is not installed", "models": []}
    )
    assert normalized["status"] == "unknown"
    assert normalized["counterexamples"] == []


def test_z3_executor_returns_valid_status_without_requiring_solver() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    raw = run_authorization_obligation_with_z3(obligation)
    assert raw["status"] in {"pass", "fail", "unknown"}


@pytest.mark.skipif(__import__("importlib.util").util.find_spec("z3") is None, reason="z3-solver is not installed")
def test_z3_executor_finds_violation_when_solver_installed() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    raw = run_authorization_obligation_with_z3(obligation)
    assert raw["status"] == "fail"
    assert raw["models"]
