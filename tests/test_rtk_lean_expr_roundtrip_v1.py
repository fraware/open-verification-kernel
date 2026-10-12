"""Synthetic adversarial checks. Real decoder/kernel witness is CI-native Lean."""

from __future__ import annotations

import copy
import json

import pytest

from experiments.rtk.lean_expr_roundtrip_v1 import (
    _result,
    attest_local_roundtrip,
)

NAT = ["const", ["str", ["anonymous"], "Nat"], []]
TYPE = ["forallE", ["str", ["anonymous"], "n"], NAT, NAT, "default"]
OLD = ["lam", ["str", ["anonymous"], "n"], NAT, ["bvar", 0], "default"]
NEW = ["lam", ["str", ["anonymous"], "n"], NAT, ["natVal", 0], "default"]
PROOF = ["const", ["str", ["anonymous"], "Eq.refl"], []]


def _structural(*, target=False):
    r = {
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "rtk_unproven_target_claim" if target else "historical_claim",
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": TYPE,
        "theorem_value_ast": None if target else PROOF,
        "op_name": "op", "op_type_ast": NAT,
        "op_value_ast": NEW if target else OLD,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    }
    return "file: info: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(r)


def _roundtrip(*, target=False):
    r = {
        "schema_version": "rtk.lean_native_expr_roundtrip.v1-development",
        "root_name": "rtk_unproven_target_claim" if target else "historical_claim",
        "root_kind": "axiom" if target else "theorem",
        "root_type_ast": TYPE,
        "root_proof_ast": None if target else PROOF,
        "op_type_ast": NAT, "op_value_ast": NEW if target else OLD,
        "source_proof_kernel_checked": not target,
        "target_old_proof_replayed": False,
        "target_claim_established": False,
        "decode_encode_ast_equal": True,
        "decode_native_expr_equal": True,
        "malformed_metavar_rejected": True,
        "forged_imported_definition_rejected": True,
        "semantic_support_complete": False,
        "cross_environment_transport_established": False,
    }
    return "file: info: RTK_NATIVE_ROUNDTRIP_JSON=" + json.dumps(r)


def _kwargs():
    return {
        "source_roundtrip_log": _roundtrip(),
        "target_roundtrip_log": _roundtrip(target=True),
        "source_structural_log": _structural(),
        "target_structural_log": _structural(target=True),
    }


def test_roundtrip_record_matches_native_source_and_target_records():
    out = attest_local_roundtrip(**_kwargs())
    assert out["native_source_decoded_proof_kernel_checked"] is True
    assert out["target_claim_established"] is False
    assert out["historical_transport_applicability"] == "UNDETERMINED"
    assert out["native_decoder_formally_verified"] is False
    assert out["reliance_authorization"] is False


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"decode_native_expr_equal": False}, "roundtrip or anti-tamper"),
        ({"malformed_metavar_rejected": False}, "roundtrip or anti-tamper"),
        ({"source_proof_kernel_checked": False}, "not kernel checked"),
        ({"target_old_proof_replayed": True}, "unsupported native transport"),
        ({"cross_environment_transport_established": True}, "unsupported native transport"),
        ({"native_decoding_unchecked": True}, "evidence shape"),
        ({"root_kind": "axiom"}, "source proof"),
    ],
)
def test_reject_bad_source_native_witness(change, reason):
    data = _kwargs()
    raw = json.loads(data["source_roundtrip_log"].split("RTK_NATIVE_ROUNDTRIP_JSON=", 1)[1])
    raw.update(change)
    data["source_roundtrip_log"] = "RTK_NATIVE_ROUNDTRIP_JSON=" + json.dumps(raw)
    with pytest.raises(ValueError, match=reason):
        attest_local_roundtrip(**data)


def test_target_goal_cannot_carry_a_checked_proof():
    data = _kwargs()
    raw = json.loads(data["target_roundtrip_log"].split("RTK_NATIVE_ROUNDTRIP_JSON=", 1)[1])
    raw["root_proof_ast"] = PROOF
    data["target_roundtrip_log"] = "RTK_NATIVE_ROUNDTRIP_JSON=" + json.dumps(raw)
    with pytest.raises(ValueError, match="unproved target"):
        attest_local_roundtrip(**data)


def test_roundtrip_native_ast_mismatch_rejected():
    data = _kwargs()
    r = json.loads(data["source_roundtrip_log"].split("RTK_NATIVE_ROUNDTRIP_JSON=", 1)[1])
    r["op_value_ast"] = ["natVal", 99]
    data["source_roundtrip_log"] = "RTK_NATIVE_ROUNDTRIP_JSON=" + json.dumps(r)
    with pytest.raises(ValueError, match="contradicts prior"):
        attest_local_roundtrip(**data)


def test_structural_name_ambiguity_refused():
    data = _kwargs()
    r = json.loads(data["target_roundtrip_log"].split("RTK_NATIVE_ROUNDTRIP_JSON=", 1)[1])
    r["op_value_ast"] = ["const", ["num", ["anonymous"], 0], []]
    data["target_roundtrip_log"] = "RTK_NATIVE_ROUNDTRIP_JSON=" + json.dumps(r)
    with pytest.raises(ValueError, match="contradicts prior"):
        attest_local_roundtrip(**data)


def test_duplicate_native_marker_refused():
    with pytest.raises(ValueError, match="one bounded"):
        _result(_roundtrip() + "\n" + _roundtrip())
