import shutil
from pathlib import Path

import pytest

from ovk.adapters.opa.optional_runner import run_opa_policy


@pytest.mark.skipif(shutil.which("opa") is None, reason="OPA binary is not installed")
def test_optional_opa_runner_detects_removed_gate_when_opa_installed() -> None:
    result = run_opa_policy(
        policy_path=Path("adapters/opa/policies/self_protection.rego"),
        input_path=Path("examples/no_agent_self_approval/input_gate_removed.json"),
    )
    assert result["status"] == "fail"
    assert result["violations"]


@pytest.mark.skipif(shutil.which("opa") is None, reason="OPA binary is not installed")
def test_optional_opa_runner_allows_preserved_gate_when_opa_installed() -> None:
    result = run_opa_policy(
        policy_path=Path("adapters/opa/policies/self_protection.rego"),
        input_path=Path("examples/no_agent_self_approval/input_gate_preserved.json"),
    )
    assert result["status"] == "pass"
    assert result["violations"] == []
