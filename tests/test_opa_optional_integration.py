from pathlib import Path

import pytest

from ovk.adapters.opa.optional_runner import run_opa_policy
from tests.native_ci import skip_unless_native_backend


@pytest.mark.skipif(skip_unless_native_backend("opa"), reason="OPA integration runs in tier-1 workflow")
def test_optional_opa_runner_detects_removed_gate_when_opa_installed() -> None:
    result = run_opa_policy(
        policy_path=Path("adapters/opa/policies/self_protection.rego"),
        input_path=Path("examples/no_agent_self_approval/input_gate_removed.json"),
    )
    assert result["status"] == "fail"
    assert result["violations"]


@pytest.mark.skipif(skip_unless_native_backend("opa"), reason="OPA integration runs in tier-1 workflow")
def test_optional_opa_runner_allows_preserved_gate_when_opa_installed() -> None:
    result = run_opa_policy(
        policy_path=Path("adapters/opa/policies/self_protection.rego"),
        input_path=Path("examples/no_agent_self_approval/input_gate_preserved.json"),
    )
    assert result["status"] == "pass"
    assert result["violations"] == []
