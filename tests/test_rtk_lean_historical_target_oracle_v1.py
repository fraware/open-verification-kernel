"""Synthetic integrity tests; native Lean replay runs only in dedicated CI."""

from __future__ import annotations

import json

import pytest

from experiments.rtk.lean_historical_target_oracle_v1 import (
    export_target_claim, verify_target_replay,
)
from experiments.rtk.lean_structural_expr_v1 import _canonical, _digest

_EXPR = ["sort", ["zero"]]


def _source() -> bytes:
    return _canonical({
        "schema_version": "rtk.lean_separate_source_proof_payload.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": _EXPR,
        "proof_ast": _EXPR,
        "source_native_log_sha256": "a" * 64,
        "source_checked_file_sha256": "b" * 64,
        "source_proof_expr_ast_sha256": _digest(_EXPR),
        "historical_transport_applicability": "UNDETERMINED",
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False,
        "reliance_authorization": False,
    })


def _target_native(*, kind="axiom", value=None) -> str:
    return "Lean: info: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "rtk_unproven_target_claim",
        "theorem_kind": kind,
        "theorem_type_ast": _EXPR,
        "theorem_value_ast": value,
        "op_name": "op",
        "op_type_ast": _EXPR,
        "op_value_ast": _EXPR,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    })


def _case(decision: str = "ADMISSIBLE") -> dict:
    source = _source()
    target = _canonical(export_target_claim(
        source_payload_bytes=source, target_native_log=_target_native(),
    ))
    checked = decision != "UNDETERMINED"
    defeq = decision == "ADMISSIBLE"
    witness = {
        "schema_version": "rtk.lean_historical_target_replay.v1-development",
        "source_proof_ast": _EXPR,
        "target_claim_ast": _EXPR,
        "kernel_check_accepted": checked,
        "inferred_type_defeq_target_claim": defeq,
        "adjudication": decision,
        "target_theorem_or_placeholder_preloaded": False,
        "fresh_target_proof_supplied_to_oracle": False,
        "rtk_predictor_consulted": False,
        "relying_authority": False,
        "semantic_support_soundness_proved": False,
    }
    return {
        "source_payload_bytes": source,
        "target_payload_bytes": target,
        "driver_bytes": b"import Lean\n",
        "module_bytes": b"actual development module",
        "native_log": "Lean: info: RTK_HISTORICAL_TARGET_REPLAY_JSON=" +
                      json.dumps(witness),
        "expected_decision": decision,
    }


@pytest.mark.parametrize("decision", [
    "ADMISSIBLE", "INADMISSIBLE", "UNDETERMINED",
])
def test_exact_native_decision_normalization(decision):
    record = verify_target_replay(**_case(decision))
    assert record["historical_certificate_adjudication"] == decision
    assert record["target_claim_truth_adjudicated"] is False
    assert record["production_reliance_authorized"] is False
    assert record["predictor_consulted"] is False
    assert record["complete_semantic_support_proved"] is False


def test_unproved_target_claim_only():
    with pytest.raises(ValueError, match="unexpected checked source theorem"):
        export_target_claim(
            source_payload_bytes=_source(),
            target_native_log=_target_native(kind="theorem", value=_EXPR),
        )


def test_target_claim_must_equal_source_statement_ast():
    case = _case()
    target = json.loads(case["target_payload_bytes"])
    target["claim_ast"] = ["natVal", 0]
    target["claim_ast_sha256"] = _digest(target["claim_ast"])
    case["target_payload_bytes"] = _canonical(target)
    with pytest.raises(ValueError, match="source/target export mismatch"):
        verify_target_replay(**case)


def _tamper(case: dict, key: str, value):
    prefix, text = case["native_log"].split(
        "RTK_HISTORICAL_TARGET_REPLAY_JSON=", 1
    )
    witness = json.loads(text)
    witness[key] = value
    case["native_log"] = prefix + "RTK_HISTORICAL_TARGET_REPLAY_JSON=" + (
        json.dumps(witness)
    )


@pytest.mark.parametrize(("field", "value", "error"), [
    ("rtk_predictor_consulted", True, "leaked external reliance"),
    ("relying_authority", True, "leaked external reliance"),
    ("semantic_support_soundness_proved", True, "leaked external reliance"),
    ("fresh_target_proof_supplied_to_oracle", True, "leaked external reliance"),
    ("source_proof_ast", ["natVal", 1], "substituted certificate"),
    ("target_claim_ast", ["natVal", 1], "substituted certificate"),
    ("inferred_type_defeq_target_claim", False, "inconsistent with kernel"),
    ("adjudication", "INADMISSIBLE", "inconsistent with kernel"),
])
def test_native_witness_adversarial_tamper(field, value, error):
    case = _case()
    _tamper(case, field, value)
    with pytest.raises(ValueError, match=error):
        verify_target_replay(**case)


def test_source_payload_digest_mismatch_is_rejected():
    case = _case()
    source = json.loads(case["source_payload_bytes"])
    source["proof_ast"] = ["natVal", 1]
    case["source_payload_bytes"] = _canonical(source)
    with pytest.raises(ValueError, match="source proof AST"):
        verify_target_replay(**case)


def test_case_is_not_labeled_by_an_expected_answer():
    case = _case("INADMISSIBLE")
    case["expected_decision"] = "ADMISSIBLE"
    with pytest.raises(ValueError, match="disagrees with development control"):
        verify_target_replay(**case)


def test_duplicate_native_oracle_markers_fail_closed():
    case = _case()
    case["native_log"] += "\n" + case["native_log"]
    with pytest.raises(ValueError, match="one native historical replay"):
        verify_target_replay(**case)


def test_unadjudicated_oracle_does_not_imply_inadmissible():
    record = verify_target_replay(**_case("UNDETERMINED"))
    assert record["historical_certificate_adjudication"] == "UNDETERMINED"
    assert record["target_claim_truth_adjudicated"] is False


def test_driver_and_target_olean_bytes_are_required():
    case = _case()
    case["driver_bytes"] = b""
    with pytest.raises(ValueError, match="missing target checker"):
        verify_target_replay(**case)
