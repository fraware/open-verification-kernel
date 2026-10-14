"""Development adversarial tests for freshly exported patched Lean evidence."""
from __future__ import annotations

import json

import pytest

from experiments.rtk.lean_patched_historical_v1 import (
    reexport_source, seal_patched_contexts, require_sealed_before_oracle,
)

NAT = ["const", ["str", ["anonymous"], "Nat"], []]
TYPE = ["forallE", ["str", ["anonymous"], "n"], NAT, ["sort", ["zero"]], "default"]
OP_SRC = ["lam", ["str", ["anonymous"], "n"], NAT, ["bvar", 0], "default"]
OP_DRIFT = ["lam", ["str", ["anonymous"], "n"], NAT, [
    "app", ["const", ["str", ["anonymous"], "Nat.zero_add"], []], ["bvar", 0],
], "default"]
PROOF = ["app", ["const", ["str", ["anonymous"], "Eq.refl"], []], NAT]


def native(*, target=False, drift=False):
    return "native: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "rtk_unproven_target_claim" if target else "historical_claim",
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": TYPE,
        "theorem_value_ast": None if target else PROOF,
        "op_name": "op",
        "op_type_ast": TYPE,
        "op_value_ast": OP_DRIFT if drift else OP_SRC,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    })


def case():
    source = native()
    payload = reexport_source(source, b"theorem historical_claim := Eq.refl n")
    args = {
        "historical_source_payload": payload,
        "source_structural_log": source,
        "target_equal_log": native(target=True),
        "target_changed_log": native(target=True, drift=True),
        "checker_binary_sha256": "a" * 64,
        "source_module": b"source_module",
        "target_equal_module": b"target_equal_module",
        "target_changed_module": b"target_changed_module",
    }
    return args


def test_patched_source_reexport_and_two_unproved_targets_sealed():
    args = case()
    record = seal_patched_contexts(**args)
    require_sealed_before_oracle(
        record, args["historical_source_payload"],
        args["target_equal_log"], args["target_changed_log"],
    )
    assert record["source_proof_reexported_under_patched_lean"] is True
    assert record["target_claims_unproved_before_oracle"] is True
    assert record["historical_target_replay_executed"] is False
    assert record["production_reliance_authorized"] is False
    assert record["checker_version"] == "4.35.0"


def test_wrong_source_theorem_rejected():
    with pytest.raises(ValueError, match="checked historical theorem"):
        reexport_source(native(target=True), b"source")


def test_equal_case_definition_substitution_rejected():
    args = case()
    args["target_equal_log"] = native(target=True, drift=True)
    with pytest.raises(ValueError, match="equal target unexpectedly"):
        seal_patched_contexts(**args)


def test_changed_case_that_does_not_change_definition_rejected():
    args = case()
    args["target_changed_log"] = native(target=True)
    with pytest.raises(ValueError, match="changed target has no observed"):
        seal_patched_contexts(**args)


def test_target_claim_proof_substitution_rejected():
    args = case()
    bad = json.loads(args["target_equal_log"].split("RTK_STRUCTURAL_EXPR_JSON=", 1)[1])
    bad["theorem_kind"] = "theorem"
    bad["theorem_value_ast"] = PROOF
    args["target_equal_log"] = "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(bad)
    with pytest.raises(ValueError, match="unproved target"):
        seal_patched_contexts(**args)


def test_nonidentical_claim_ast_rejected():
    args = case()
    bad = json.loads(args["target_equal_log"].split("RTK_STRUCTURAL_EXPR_JSON=", 1)[1])
    bad["theorem_type_ast"] = NAT
    args["target_equal_log"] = "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(bad)
    with pytest.raises(ValueError, match="mismatched statement"):
        seal_patched_contexts(**args)


def test_source_log_digest_substitution_rejected():
    args = case()
    payload = json.loads(args["historical_source_payload"])
    payload["source_native_log_sha256"] = "0" * 64
    args["historical_source_payload"] = json.dumps(payload).encode()
    with pytest.raises(ValueError, match="source transcript was substituted"):
        seal_patched_contexts(**args)


def test_corrupt_binary_fingerprint_rejected():
    args = case()
    args["checker_binary_sha256"] = "not-a-digest"
    with pytest.raises(ValueError, match="executable fingerprint"):
        seal_patched_contexts(**args)


def test_mutated_sealed_record_fails_closed():
    args = case()
    record = seal_patched_contexts(**args)
    record["production_reliance_authorized"] = True
    with pytest.raises(ValueError, match="contaminated patched"):
        require_sealed_before_oracle(
            record, args["historical_source_payload"],
            args["target_equal_log"], args["target_changed_log"],
        )


def test_oracle_contaminated_manifest_rejected():
    args = case()
    record = seal_patched_contexts(**args)
    record["historical_target_replay_executed"] = True
    with pytest.raises(ValueError, match="contaminated patched"):
        require_sealed_before_oracle(
            record, args["historical_source_payload"],
            args["target_equal_log"], args["target_changed_log"],
        )
