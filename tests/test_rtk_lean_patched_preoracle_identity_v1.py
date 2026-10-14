"""Adversarial pre-oracle screening tests for pinned patched Lean (no target replay)."""
import hashlib
import json

import pytest

from experiments.rtk.lean_historical_target_oracle_v1 import export_target_claim
from experiments.rtk.lean_patched_historical_certificate_v1 import export_source
from experiments.rtk import lean_patched_preoracle_identity_v1 as m


def _n(name):
    return ["str", ["anonymous"], name]


def _e(name):
    return ["const", _n(name), []]


def _native(*, target=False, changed=False):
    root = "rtk_unproven_target_claim" if target else "historical_claim"
    return "native: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": root,
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": _e("op"),
        "theorem_value_ast": None if target else _e("Eq.refl"),
        "op_name": "op",
        "op_type_ast": _e("Nat"),
        "op_value_ast": _e("Nat.add") if changed else _e("Nat"),
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    })


def _recheck():
    return "native: RTK_SECOND_PROCESS_PROOF_JSON=" + json.dumps({
        "schema_version": "rtk.lean_second_process_kernel_check.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": _e("op"),
        "proof_ast": _e("Eq.refl"),
        "source_proof_kernel_checked": True,
        "source_proof_type_defeq_serialized_claim": True,
        "historical_theorem_not_imported_or_declared": True,
        "serialized_expr_loaded_from_disk": True,
        "independent_process_from_serializer": True,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "independently_governed_provenance": False,
        "transitive_support_completeness_proved": False,
        "transport_applicability_established": False,
    })


def _case(monkeypatch, *, changed=False, unrelated=False):
    fake_binary = b"patched-test-checker"
    monkeypatch.setattr(m, "_EXPECTED_LEAN_SHA",
                        hashlib.sha256(fake_binary).hexdigest())
    source_text = b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n\n"
    source_log = _native()
    source = export_source(source_log, source_text)
    target_log = _native(target=True, changed=changed)
    target = export_target_claim(
        source_payload_bytes=source, target_native_log=target_log
    )
    support = b"source imported module"
    target_support = (b"changed definition" if changed
                      else b"unrelated extra declaration" if unrelated
                      else support)
    return {
        "source_payload_bytes": source,
        "checked_source_bytes": source_text,
        "source_structural_log": source_log,
        "source_recheck_log": _recheck(),
        "target_payload_bytes": json.dumps(target).encode(),
        "target_structural_log": target_log,
        "source_support_olean": support,
        "target_support_olean": target_support,
        "checker_binary_bytes": fake_binary,
    }


def test_identical_imported_bytes_only_conditional(monkeypatch):
    result = m.evaluate_patched_preoracle(**_case(monkeypatch))
    assert result["decision"] == "CONDITIONAL_IDENTITY_CANDIDATE"
    assert result["reason_code"] == "exact_imported_support_bytes_and_native_definition_ast"
    assert result["target_historical_proof_replayed"] is False
    assert result["complete_kernel_semantic_support_proved"] is False
    assert result["source_target_environment_equivalence_proved"] is False
    assert result["production_reliance_authorization"] is False


def test_definition_drift_fails_closed(monkeypatch):
    result = m.evaluate_patched_preoracle(**_case(monkeypatch, changed=True))
    assert result["decision"] == "REVALIDATION_REQUIRED"
    assert result["reason_code"] == "imported_op_definition_structural_drift"


def test_unrelated_module_change_revalidation_cost(monkeypatch):
    result = m.evaluate_patched_preoracle(**_case(monkeypatch, unrelated=True))
    assert result["decision"] == "REVALIDATION_REQUIRED"
    assert result["observed_imported_definition_ast_identical"] is True
    assert result["imported_module_bytes_identical"] is False
    assert result["reason_code"] == "whole_import_module_drift_with_unchanged_observed_op"


def test_matching_bytes_cannot_hide_op_ast_disagreement(monkeypatch):
    case = _case(monkeypatch, changed=True)
    case["target_support_olean"] = case["source_support_olean"]
    with pytest.raises(ValueError, match="contradictory definition AST"):
        m.evaluate_patched_preoracle(**case)


def test_source_recheck_required_before_positive_candidate(monkeypatch):
    case = _case(monkeypatch)
    case["source_recheck_log"] = ""
    with pytest.raises(ValueError, match="one bounded native evidence marker"):
        m.evaluate_patched_preoracle(**case)


def test_source_native_proof_identity_mismatch_rejected(monkeypatch):
    case = _case(monkeypatch)
    case["source_recheck_log"] = _recheck().replace("Eq.refl", "bogus")
    with pytest.raises(ValueError, match="source proof native witness"):
        m.evaluate_patched_preoracle(**case)


def test_source_checked_file_change_rejected(monkeypatch):
    case = _case(monkeypatch)
    case["checked_source_bytes"] += b"--changed\n"
    with pytest.raises(ValueError, match="different source input"):
        m.evaluate_patched_preoracle(**case)


def test_target_unproved_placeholder_cannot_claim_proof(monkeypatch):
    case = _case(monkeypatch)
    target = json.loads(case["target_payload_bytes"])
    target["native_target_proof_replay_executed"] = True
    case["target_payload_bytes"] = json.dumps(target).encode()
    with pytest.raises(ValueError, match="not bound"):
        m.evaluate_patched_preoracle(**case)


def test_native_target_claim_cannot_mutate_unnoticed(monkeypatch):
    case = _case(monkeypatch)
    case["target_structural_log"] = _native(target=True).replace(
        '"theorem_kind": "axiom"', '"theorem_kind": "theorem"'
    )
    with pytest.raises(ValueError):
        m.evaluate_patched_preoracle(**case)


def test_nonpinned_checker_cannot_admit_any_candidate(monkeypatch):
    case = _case(monkeypatch)
    case["checker_binary_bytes"] = b"other compiler"
    with pytest.raises(ValueError, match="unsupported or altered patched Lean"):
        m.evaluate_patched_preoracle(**case)
