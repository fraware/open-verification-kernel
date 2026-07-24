"""VA-12 conformance harness + VA-13 adjudication importer tests."""

from __future__ import annotations

import json
from pathlib import Path
from shutil import which

import pytest

from ovk.adapters.assurance.auth_state import AuthoritativeStateAdapter
from ovk.adapters.assurance.model_judge import ModelJudgeAdapter
from ovk.adapters.assurance.pytest_suite import PytestSuiteAdapter
from ovk.adapters.assurance.sql_diff import SqlStateDiffAdapter
from ovk.assurance.adjudication import (
    AdjudicationImportError,
    import_adjudication_reference,
    refuse_labels_in_verifier_input,
)
from ovk.assurance.conformance import ConformanceCase, gate_assurance_adapters, write_example_pack
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.runner import run_assurance
from tests.assurance.support.make_sql_fixtures import main as make_sql

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PCS_AVAILABLE = resolve_pcs_root() is not None
requires_pcs = pytest.mark.skipif(not PCS_AVAILABLE, reason="PCS pin unavailable")


@requires_pcs
def test_conformance_gate_core_offline_adapters(tmp_path: Path) -> None:
    make_sql()
    suite = FIXTURES / "pytest_suite"
    before = FIXTURES / "sql" / "before.sqlite"
    after = FIXTURES / "sql" / "after.sqlite"

    cases = [
        ConformanceCase(
            adapter=AuthoritativeStateAdapter(),
            input_data={
                "authoritative_state": {"status": "ok", "roles": ["a"]},
                "predicates": [
                    {"kind": "field_equals", "path": "status", "expected": "ok"},
                    {"kind": "set_contains", "path": "roles", "member": "a"},
                ],
            },
            config={"timeout_ms": 1000},
            alt_config={"timeout_ms": 2000},
            unsupported_input={},
            expect_accept=True,
        ),
        ConformanceCase(
            adapter=PytestSuiteAdapter(),
            input_data={"suite_path": str(suite)},
            config={"timeout_ms": 60_000, "threshold": 0, "suite_path": str(suite)},
            alt_config={"timeout_ms": 60_001, "threshold": 0, "suite_path": str(suite)},
            unsupported_input={},
            mutation_class="reduce_test_subset",
            mutation_parameters={"test_ids": ["test_fixture_passes"]},
            expect_accept=True,
        ),
        ConformanceCase(
            adapter=SqlStateDiffAdapter(),
            input_data={
                "before_db": str(before),
                "after_db": str(after),
                "expect_changed_tables": ["items"],
            },
            config={"timeout_ms": 5000, "before_db": str(before), "after_db": str(after)},
            alt_config={"timeout_ms": 5001, "before_db": str(before), "after_db": str(after)},
            unsupported_input={},
            expect_accept=True,
        ),
        ConformanceCase(
            adapter=ModelJudgeAdapter(),
            input_data={"prompt": "hello", "rubric": {"threshold": "0.0"}, "judge_client": "contract_fake"},
            config={
                "timeout_ms": 1000,
                "prompt": "hello",
                "rubric": {"threshold": "0.0"},
                "judge_client": "contract_fake",
            },
            alt_config={
                "timeout_ms": 1001,
                "prompt": "hello",
                "rubric": {"threshold": "0.0"},
                "judge_client": "contract_fake",
            },
            unsupported_input={},
            mutation_class="change_prompt",
            mutation_parameters={"prompt": "mutated prompt"},
            expect_accept=True,
        ),
    ]

    # OPA / Lean included when toolchains exist (real runs only).
    if which("opa") is not None:
        from ovk.adapters.assurance.opa_policy import OpaPolicyAssuranceAdapter

        policy = (FIXTURES / "opa" / "allow_read.rego").read_text(encoding="utf-8")
        cases.append(
            ConformanceCase(
                adapter=OpaPolicyAssuranceAdapter(),
                input_data={
                    "policy": policy,
                    "query": "data.ovk.assurance.violation",
                    "input": {"action": "read"},
                },
                config={"timeout_ms": 10_000, "policy": policy, "query": "data.ovk.assurance.violation"},
                alt_config={"timeout_ms": 10_001, "policy": policy, "query": "data.ovk.assurance.violation"},
                unsupported_input={},
                mutation_class="policy_bundle",
                mutation_parameters={"policy": policy + "\n# mutated\n"},
                expect_accept=True,
            )
        )
    if which("lean") is not None:
        from ovk.adapters.assurance.lean_pfcore import LeanPfCoreAssuranceAdapter

        cases.append(
            ConformanceCase(
                adapter=LeanPfCoreAssuranceAdapter(),
                input_data={"lean_source": "#check Nat\n"},
                config={"timeout_ms": 60_000},
                alt_config={"timeout_ms": 60_001},
                unsupported_input={},
                expect_accept=True,
            )
        )

    report = gate_assurance_adapters(cases)
    if not report["passed"]:
        pytest.fail(json.dumps(report["failures"], indent=2))

    # Example pack for auth-state
    pack_dir = tmp_path / "examples" / "auth-state-predicate"
    write_example_pack(
        AuthoritativeStateAdapter(),
        out_dir=pack_dir,
        input_data={
            "authoritative_state": {"status": "ok"},
            "predicates": [{"kind": "field_equals", "path": "status", "expected": "ok"}],
        },
        config={"timeout_ms": 1000},
    )
    assert (pack_dir / "invocation.json").is_file()


def test_adjudication_requires_freeze(tmp_path: Path) -> None:
    marker = tmp_path / "freeze.json"
    marker.write_text(json.dumps({"campaign_id": "c1", "frozen": False}), encoding="utf-8")
    with pytest.raises(AdjudicationImportError):
        import_adjudication_reference(
            freeze_marker_path=marker,
            adjudication_ref={"reference_id": "adj-1"},
        )


def test_adjudication_import_and_audit(tmp_path: Path) -> None:
    marker = tmp_path / "freeze.json"
    marker.write_text(
        json.dumps({"campaign_id": "campaign-42", "frozen": True, "frozen_at": "2026-07-24T00:00:00Z"}),
        encoding="utf-8",
    )
    audit = tmp_path / "audit.jsonl"
    record = import_adjudication_reference(
        freeze_marker_path=marker,
        adjudication_ref={"reference_id": "adj-1", "artifact_digest": "sha256:" + ("ab" * 32)},
        audit_log_path=audit,
    )
    assert record["campaign_id"] == "campaign-42"
    assert record["label_isolation"]["hidden_labels_accessible"] is False
    assert audit.is_file()
    line = audit.read_text(encoding="utf-8").strip()
    assert "ovk.assurance.adjudication_import.v1" in line


def test_adjudication_refuses_hidden_labels(tmp_path: Path) -> None:
    marker = tmp_path / "freeze.json"
    marker.write_text(json.dumps({"campaign_id": "c1", "frozen": True}), encoding="utf-8")
    with pytest.raises(AdjudicationImportError):
        import_adjudication_reference(
            freeze_marker_path=marker,
            adjudication_ref={"reference_id": "adj-1", "hidden_label": "SECRET"},
        )
    with pytest.raises(AdjudicationImportError):
        refuse_labels_in_verifier_input({"hidden_labels": ["x"]})


@requires_pcs
def test_verifier_run_refuses_embedded_labels() -> None:
    with pytest.raises(AdjudicationImportError):
        refuse_labels_in_verifier_input(
            {
                "authoritative_state": {"status": "ok"},
                "holdout_label": "should-not-leak",
            }
        )
    # Positive path still works without labels
    outcome = run_assurance(
        AuthoritativeStateAdapter(),
        input_data={
            "authoritative_state": {"status": "ok"},
            "predicates": [{"kind": "field_equals", "path": "status", "expected": "ok"}],
        },
        config={"timeout_ms": 1000},
    )
    assert outcome.decision == "accept"
