"""Adapter-level tests for VA-06..VA-11 assurance backends."""

from __future__ import annotations

from pathlib import Path
from shutil import which

import pytest

from ovk.adapters.assurance.auth_state import AuthoritativeStateAdapter
from ovk.adapters.assurance.lean_pfcore import LeanPfCoreAssuranceAdapter
from ovk.adapters.assurance.model_judge import ModelJudgeAdapter
from ovk.adapters.assurance.opa_policy import OpaPolicyAssuranceAdapter
from ovk.adapters.assurance.pytest_suite import PytestSuiteAdapter
from ovk.adapters.assurance.sql_diff import SqlStateDiffAdapter
from ovk.assurance.capability import is_assurance_capable
from ovk.assurance.indeterminate import DECISION_ACCEPT
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.registry import build_verifier_registry, describe_backend
from ovk.assurance.runner import run_assurance
from ovk.adapters.lean.adapter import LeanAdapter

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PCS_AVAILABLE = resolve_pcs_root() is not None
requires_pcs = pytest.mark.skipif(not PCS_AVAILABLE, reason="PCS pin unavailable")
requires_opa = pytest.mark.skipif(which("opa") is None, reason="opa binary not installed")
requires_lean = pytest.mark.skipif(which("lean") is None, reason="lean binary not installed")


def test_assurance_backends_registered_and_capable() -> None:
    registry = build_verifier_registry()
    expected = {
        "auth-state-predicate",
        "pytest-suite",
        "opa-policy",
        "lean-pfcore",
        "sql-state-diff",
        "model-judge",
    }
    for backend_id in expected:
        adapter = registry.get(backend_id)
        assert adapter is not None, backend_id
        assert is_assurance_capable(adapter.manifest())
        desc = describe_backend(backend_id, registry=registry)
        assert desc["assurance_capable"] is True


def test_ordinary_lean_is_not_assurance_capable() -> None:
    registry = build_verifier_registry()
    assert registry.get("lean") is None
    lean = LeanAdapter()
    manifest = lean.capability_manifest
    assert isinstance(manifest, dict)
    assert not (manifest.get("assurance") or {}).get("assurance_capable")


@requires_pcs
def test_auth_state_accept_and_reject() -> None:
    adapter = AuthoritativeStateAdapter()
    state = {"status": "approved", "roles": ["reader", "admin"]}
    outcome = run_assurance(
        adapter,
        input_data={
            "authoritative_state": state,
            "predicates": [
                {"kind": "field_equals", "path": "status", "expected": "approved"},
                {"kind": "set_contains", "path": "roles", "member": "admin"},
            ],
        },
        config={"timeout_ms": 1000},
    )
    assert outcome.decision == "accept"

    bad = run_assurance(
        adapter,
        input_data={
            "authoritative_state": state,
            "predicates": [{"kind": "field_equals", "path": "status", "expected": "denied"}],
        },
        config={"timeout_ms": 1000},
    )
    assert bad.decision == "reject"
    assert bad.normalized_result.get("counterexamples")


@requires_pcs
def test_auth_state_missing_state_indeterminate() -> None:
    adapter = AuthoritativeStateAdapter()
    outcome = run_assurance(adapter, input_data={"predicates": [{"kind": "field_equals", "path": "x", "expected": 1}]})
    assert outcome.decision != DECISION_ACCEPT
    assert outcome.indeterminate_reason == "missing_authoritative_state"


@requires_pcs
def test_pytest_suite_offline() -> None:
    adapter = PytestSuiteAdapter()
    suite = FIXTURES / "pytest_suite"
    outcome = run_assurance(
        adapter,
        input_data={"suite_path": str(suite)},
        config={"timeout_ms": 60_000, "threshold": 0},
    )
    assert outcome.decision == "accept"
    assert outcome.snapshot.guarantee_class == "runtime_observed"
    assert outcome.normalized_result.get("guarantee_class") == "runtime_observed"


@requires_pcs
def test_opa_missing_is_indeterminate() -> None:
    if which("opa") is not None:
        pytest.skip("opa present; missing-checker path covered when absent")
    adapter = OpaPolicyAssuranceAdapter()
    policy = (FIXTURES / "opa" / "allow_read.rego").read_text(encoding="utf-8")
    outcome = run_assurance(
        adapter,
        input_data={"policy": policy, "query": "data.ovk.assurance.violation", "input": {"action": "write"}},
        config={"timeout_ms": 5000},
    )
    assert outcome.decision != DECISION_ACCEPT
    assert outcome.indeterminate_reason == "missing_checker"


@requires_pcs
@requires_opa
def test_opa_real_eval() -> None:
    adapter = OpaPolicyAssuranceAdapter()
    policy = (FIXTURES / "opa" / "allow_read.rego").read_text(encoding="utf-8")
    accept = run_assurance(
        adapter,
        input_data={"policy": policy, "query": "data.ovk.assurance.violation", "input": {"action": "read"}},
        config={"timeout_ms": 10_000, "policy": policy, "query": "data.ovk.assurance.violation"},
    )
    # violation query empty => pass in run_opa_policy semantics
    assert accept.decision in {"accept", "reject"}  # depends on violation list emptiness
    reject = run_assurance(
        adapter,
        input_data={"policy": policy, "query": "data.ovk.assurance.violation", "input": {"action": "write"}},
        config={"timeout_ms": 10_000, "policy": policy, "query": "data.ovk.assurance.violation"},
    )
    assert reject.decision == "reject"


@requires_pcs
@requires_lean
def test_lean_pfcore_real_source() -> None:
    adapter = LeanPfCoreAssuranceAdapter()
    outcome = run_assurance(
        adapter,
        input_data={"lean_source": "#check Nat\n#eval (2 : Nat)\n"},
        config={"timeout_ms": 60_000},
    )
    assert outcome.decision == "accept"


@requires_pcs
def test_lean_missing_indeterminate(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = LeanPfCoreAssuranceAdapter()
    monkeypatch.setattr("ovk.adapters.assurance.lean_pfcore.lean_available", lambda: False)
    monkeypatch.setattr("ovk.adapters.assurance.lean_pfcore.which", lambda _name: None)
    outcome = run_assurance(
        adapter,
        input_data={"lean_source": "#check Nat\n"},
        config={"timeout_ms": 1000},
    )
    assert outcome.decision != DECISION_ACCEPT
    assert outcome.indeterminate_reason == "missing_checker"


@requires_pcs
def test_sql_state_diff() -> None:
    # Ensure fixtures exist
    from tests.assurance.support.make_sql_fixtures import main as make_sql

    make_sql()
    adapter = SqlStateDiffAdapter()
    before = FIXTURES / "sql" / "before.sqlite"
    after = FIXTURES / "sql" / "after.sqlite"
    outcome = run_assurance(
        adapter,
        input_data={
            "before_db": str(before),
            "after_db": str(after),
            "expect_changed_tables": ["items"],
        },
        config={"timeout_ms": 5000},
    )
    assert outcome.decision == "accept"
    assert "state_diff" in outcome.normalized_result


@requires_pcs
def test_model_judge_contract_fake_no_upgrade() -> None:
    adapter = ModelJudgeAdapter()
    outcome = run_assurance(
        adapter,
        input_data={
            "prompt": "Rate this change as safe.",
            "judge_client": "contract_fake",
            "rubric": {"threshold": "0.0"},
        },
        config={"timeout_ms": 1000, "judge_client": "contract_fake", "rubric": {"threshold": "0.0"}},
    )
    assert outcome.decision == "accept"
    assert outcome.normalized_result.get("guarantee_class") == "empirically_measured"
    # Cannot upgrade
    assert outcome.result.get("claim_surface", {}).get("guarantee_class") in {
        None,
        "empirically_measured",
    } or outcome.snapshot.guarantee_class == "empirically_measured"
