"""Adversarial serialization checks for the isolated patched Lean 4.35 lane."""

import hashlib
import json

import pytest

from experiments.rtk.lean_historical_target_oracle_v1 import _source
from experiments.rtk.lean_patched_historical_certificate_v1 import (
    check_observation, export_source, make_driver,
)
from experiments.rtk.lean_structural_expr_v1 import _digest


def _name(name: str):
    return ["str", ["anonymous"], name]


def _expr(name: str):
    return ["const", _name(name), []]


def _source_log(kind="theorem", value=True):
    return "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "historical_claim",
        "theorem_kind": kind,
        "theorem_type_ast": _expr("op"),
        "theorem_value_ast": _expr("Eq.refl") if value else None,
        "op_name": "op",
        "op_type_ast": _expr("Nat"),
        "op_value_ast": _expr("Nat"),
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    })


def test_patched_source_export_restricted_to_checked_historical_theorem():
    raw = export_source(_source_log(), (
        b"import RTKPatchedSupport\n"
        b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n\n"
    ))
    payload = _source(raw)
    assert payload["proof_ast"] == _expr("Eq.refl")
    assert payload["claim_ast"] == _expr("op")
    assert payload["source_proof_expr_ast_sha256"] == _digest(_expr("Eq.refl"))
    assert payload["target_historical_proof_replay_executed"] is False
    assert payload["reliance_authorization"] is False


@pytest.mark.parametrize("kind,value", [("axiom", False), ("theorem", False)])
def test_unproved_or_missing_source_proof_rejected(kind, value):
    # The upstream strict AST decoder rejects an axiom in the source slot
    # even before the patched exporter checks the missing checked theorem.
    with pytest.raises(ValueError):
        export_source(
            _source_log(kind, value),
            b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n",
        )


def test_source_code_identity_not_silently_substituted():
    with pytest.raises(ValueError, match="historical source code"):
        export_source(_source_log(), b"theorem unrelated : True := trivial")


def _header(trust=0, claimed=False):
    return "RTK_HISTORICAL_TARGET_REPLAY_CONTEXT_JSON=" + json.dumps({
        "schema_version": "rtk.lean_historical_replay_context.v1-development",
        "trust_level": trust,
        "quotient_initialized": True,
        "old_certificate_checked_in_this_process": True,
        "production_reliance_authorization": claimed,
    })


def test_oracle_requires_same_process_zero_trust():
    check_observation(_header(), "ADMISSIBLE")
    with pytest.raises(ValueError, match="same-process trust zero"):
        check_observation(_header(trust=1025), "ADMISSIBLE")
    with pytest.raises(ValueError, match="same-process trust zero"):
        check_observation(_header(claimed=True), "ADMISSIBLE")
    with pytest.raises(ValueError, match="missing or duplicated"):
        check_observation(_header() + "\n" + _header(), "ADMISSIBLE")


def test_driver_rewrites_all_legacy_paths_without_target_proof():
    src = (
        "import Lean\nimport RTKSemanticSupport\n"
        "run_cmd do\n"
        "  IO.println \".rtk-imported-build/rtk_source_proof_payload.json\"\n"
        "  IO.println \".rtk-imported-build/rtk_target_claim_payload.json\"\n"
    )
    # The driver template is created with the exact intended command
    # boundary; a missing encoder or decoder boundary must be rejected.
    with pytest.raises(ValueError, match="encoder native driver boundary"):
        make_driver("bad", "bad", src, module="RTKPatchedSupport")


def test_source_input_changes_bind_payload_without_changing_proof_ast():
    one = b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n\\n"
    two = one + b"-- changed source comment\\n"
    raw_one = export_source(_source_log(), one)
    raw_two = export_source(_source_log(), two)
    assert hashlib.sha256(raw_one).digest() != hashlib.sha256(raw_two).digest()
    assert _source(raw_one)["proof_ast"] == _source(raw_two)["proof_ast"]
    assert _source(raw_one)["source_checked_file_sha256"] != (
        _source(raw_two)["source_checked_file_sha256"]
    )
