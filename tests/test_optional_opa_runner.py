from pathlib import Path

from ovk.adapters.opa.optional_runner import run_opa_policy


def test_opa_runner_returns_unknown_when_binary_missing(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = run_opa_policy(
        policy_path=Path("adapters/opa/policies/self_protection.rego"),
        input_path=Path("examples/no_agent_self_approval/input_gate_removed.json"),
    )
    assert result["status"] == "unknown"
    assert result["violations"] == []


def test_opa_runner_returns_valid_status_when_binary_available_or_missing() -> None:
    result = run_opa_policy(
        policy_path=Path("adapters/opa/policies/self_protection.rego"),
        input_path=Path("examples/no_agent_self_approval/input_gate_removed.json"),
    )
    assert result["status"] in {"pass", "fail", "unknown", "error"}
    if result["status"] == "unknown":
        assert "reason" in result
