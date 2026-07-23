import json
from pathlib import Path

from ovk.adapters.opa.optional_runner import run_opa_policy
from ovk.core.execution_budget import WorkerResult


def test_opa_runner_returns_unknown_when_binary_missing(monkeypatch) -> None:
    monkeypatch.setattr("ovk.adapters.opa.optional_runner.shutil.which", lambda name: None)
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


def test_opa_runner_does_not_treat_compile_errors_as_pass(monkeypatch, tmp_path: Path) -> None:
    """Regression: OPA JSON error payloads must never become empty-pass."""
    policy = tmp_path / "policy.rego"
    policy.write_text("package ovk.self_protection\n", encoding="utf-8")
    input_path = tmp_path / "input.json"
    input_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("ovk.adapters.opa.optional_runner.shutil.which", lambda _name: "/usr/bin/opa")

    class ErrorWorker:
        def run(self, command, *, cwd, env=None, timeout_seconds, max_stdout_bytes=0, max_stderr_bytes=0):
            payload = {
                "errors": [
                    {
                        "message": "var path declared above",
                        "code": "rego_compile_error",
                        "location": {"file": "policy.rego", "row": 16, "col": 3},
                    }
                ]
            }
            return WorkerResult(
                exit_code=2,
                timed_out=False,
                stdout=json.dumps(payload),
                stderr="",
                cwd=str(cwd),
                command=tuple(command),
            )

    result = run_opa_policy(policy_path=policy, input_path=input_path, worker=ErrorWorker())
    assert result["status"] == "error"
    assert result["violations"] == []
    assert "var path declared above" in result["reason"]
