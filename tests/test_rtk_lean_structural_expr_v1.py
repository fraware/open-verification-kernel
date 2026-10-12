"""Adversarial development tests, not substitute for actual Lean execution."""

from __future__ import annotations

import json

import pytest

from experiments.rtk.lean_structural_expr_v1 import (
    _structural_ast,
    analyze_structural_pair,
)

NAME = ["str", ["anonymous"], "Nat"]
OP = ["str", ["anonymous"], "op"]
ROOT = ["str", ["anonymous"], "historical_claim"]
SORT = ["sort", ["zero"]]
NAT = ["const", NAME, []]
TYPE = ["forallE", ["str", ["anonymous"], "n"], NAT, SORT, "default"]
OLD_VALUE = ["lam", ["str", ["anonymous"], "n"], NAT, ["bvar", 0], "default"]
NEW_VALUE = ["lam", ["str", ["anonymous"], "n"], NAT, [
    "app", ["const", OP, []], ["bvar", 0],
], "default"]
PROOF = ["app", ["const", ["str", ["anonymous"], "Eq.refl"], [
    ["succ", ["zero"]]
]], ["bvar", 0]]


def _log(*, target: bool = False, body=None) -> str:
    obj = {
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": (
            "rtk_unproven_target_claim" if target else "historical_claim"
        ),
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": TYPE,
        "theorem_value_ast": None if target else PROOF,
        "op_name": "op",
        "op_type_ast": TYPE,
        "op_value_ast": (
            NEW_VALUE if target else OLD_VALUE
        ) if body is None else body,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    }
    return "file.lean:12:0: info: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(obj)


def test_same_statement_type_but_changed_imported_body_is_detected():
    outcome = analyze_structural_pair(_log(), _log(target=True))
    assert outcome["statement_structural_ast_identical"] is True
    assert outcome["imported_definition_structural_drift"] is True
    assert outcome["source_op_value_ast_sha256"] != (
        outcome["target_op_value_ast_sha256"]
    )
    assert outcome["source_op_type_ast_sha256"] == (
        outcome["target_op_type_ast_sha256"]
    )
    assert outcome["target_historical_proof_replayed"] is False
    assert outcome["target_claim_established"] is False
    assert outcome["cross_environment_semantic_completeness_proved"] is False
    assert outcome["transport_applicability"] == "UNDETERMINED"


def test_identical_structural_body_does_not_certify_transport():
    result = analyze_structural_pair(_log(), _log(target=True, body=OLD_VALUE))
    assert result["imported_definition_structural_drift"] is False
    assert result["transport_applicability"] == "UNDETERMINED"


@pytest.mark.parametrize(
    ("bad", "error"),
    [
        (["mvar", "forged"], "unknown Lean expression"),
        (["fvar", "forged"], "unknown Lean expression"),
        (["mdata", ["bvar", 0]], "unknown Lean expression"),
        (["natVal", -1], "invalid natural"),
        (["bvar", True], "invalid bound"),
        (["sort", ["mvar", "hole"]], "unsupported universe"),
        (["const", ["str", ["anonymous"], "op"], [["mvar", "hole"]]],
         "unsupported universe"),
        (["lam", ROOT, NAT, ["bvar", 0], "other"], "binder annotation"),
        (["letE", ROOT, NAT, NAT, NAT, 1], "nondependency"),
        (["proj", OP, -1, NAT], "projection index"),
        (["const", ["num", ["anonymous"], -1], []], "Name numeral"),
    ],
)
def test_invalid_or_untrusted_native_ast_nodes_rejected(bad, error):
    with pytest.raises(ValueError, match=error):
        _structural_ast(_log(body=bad))


def test_forbidden_native_report_completeness_override():
    payload = _log().split("RTK_STRUCTURAL_EXPR_JSON=", 1)[1]
    record = json.loads(payload)
    record["imported_support_closure_proved"] = True
    with pytest.raises(ValueError, match="closure proof"):
        _structural_ast("RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(record))


def test_forged_target_proof_or_changed_subject_rejected():
    target = json.loads(_log(target=True).split("RTK_STRUCTURAL_EXPR_JSON=", 1)[1])
    target["theorem_value_ast"] = PROOF
    with pytest.raises(ValueError, match="target axiom contains"):
        analyze_structural_pair(
            _log(), "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(target)
        )
    target["theorem_value_ast"] = None
    target["theorem_name"] = "historical_claim"
    with pytest.raises(ValueError, match="native proof"):
        analyze_structural_pair(
            _log(), "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(target)
        )


def test_mismatched_native_statement_type_is_not_silently_equal():
    target = json.loads(_log(target=True).split("RTK_STRUCTURAL_EXPR_JSON=", 1)[1])
    target["theorem_type_ast"] = ["sort", ["succ", ["zero"]]]
    with pytest.raises(ValueError, match="formal source and target"):
        analyze_structural_pair(
            _log(), "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(target)
        )


def test_duplicate_native_ast_markers_not_accepted():
    a = _log()
    with pytest.raises(ValueError, match="one bounded"):
        _structural_ast(a + "\n" + a)


def test_native_name_constructor_differs_from_pretty_display():
    a = _log(target=True, body=[
        "const", ["str", ["anonymous"], "0"], []
    ])
    b = _log(target=True, body=[
        "const", ["num", ["anonymous"], 0], []
    ])
    aa = _structural_ast(a)
    bb = _structural_ast(b)
    assert aa["op_value_ast"] != bb["op_value_ast"]
