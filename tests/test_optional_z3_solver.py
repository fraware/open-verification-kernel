import json
from pathlib import Path

from ovk.adapters.z3.solver_authorization import evaluate_with_optional_z3


def test_optional_z3_path_returns_valid_status() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text())
    result = evaluate_with_optional_z3(data)
    assert result["status"] in {"pass", "fail", "unknown"}
    if result["status"] == "unknown":
        assert "reason" in result
    if result["status"] == "fail":
        assert result["counterexamples"][0]["failure_mode"] == "admin_route_reachable_by_non_admin"
