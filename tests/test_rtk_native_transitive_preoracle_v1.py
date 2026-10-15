"""Synthetic contract tests. These do not replace Lean 4.35 native replay."""
import hashlib
import json

import pytest

from experiments.rtk import lean_native_transitive_preoracle_v1 as m
from experiments.rtk import lean_patched_preoracle_identity_v1 as identity
from experiments.rtk.lean_historical_target_oracle_v1 import export_target_claim
from experiments.rtk.lean_patched_historical_certificate_v1 import export_source


def _const(name: str) -> list:
    node = ["anonymous"]
    for part in name.split("."):
        node = ["str", node, part]
    return ["const", node, []]


def _log(*, target: bool, changed_base: bool = False,
         changed_op: bool = False, omit_extra: bool = False) -> str:
    op_ast = _const("Nat") if changed_op else _const("base")
    theorem = {
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": (
            "rtk_unproven_target_claim" if target else "historical_claim"
        ),
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": _const("op"),
        "theorem_value_ast": None if target else _const("Eq.refl"),
        "op_name": "op",
        "op_type_ast": _const("Nat"),
        "op_value_ast": op_ast,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    }
    native = "RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(theorem)
    if omit_extra:
        return native
    base = {
        "schema_version": m._SCHEMA,
        "base_name": "base",
        "base_kind": "definition",
        "base_type_ast": _const("Nat"),
        "base_value_ast": _const("Nat.add" if changed_base else "Nat"),
        "op_name": "op",
        "op_kind": "definition",
        "op_value_ast": op_ast,
        "support_completeness_proved": False,
        "historical_certificate_replayed": False,
        "relying_authority": False,
    }
    return native + "\nRTK_TRANSITIVE_DECLARATION_JSON=" + json.dumps(base)


def _recheck() -> str:
    row = {
        "schema_version": "rtk.lean_second_process_kernel_check.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": _const("op"),
        "proof_ast": _const("Eq.refl"),
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
    }
    return "RTK_SECOND_PROCESS_PROOF_JSON=" + json.dumps(row)


def _case(monkeypatch, *, changed_base=False, unrelated=False,
          changed_op=False, omit_extra=False) -> dict:
    checker = b"synthetic-patched-Lean"
    monkeypatch.setattr(
        identity, "_EXPECTED_LEAN_SHA", hashlib.sha256(checker).hexdigest()
    )
    checked = b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n\n"
    source_log = _log(target=False)
    target_log = _log(
        target=True, changed_base=changed_base,
        changed_op=changed_op, omit_extra=omit_extra
    )
    source_payload = export_source(source_log, checked)
    target_payload = export_target_claim(
        source_payload_bytes=source_payload, target_native_log=target_log
    )
    source_olean = b"source support module"
    target_olean = (
        b"changed base" if changed_base else
        b"changed op" if changed_op else
        b"unrelated extension" if unrelated else
        source_olean
    )
    return {
        "source_payload_bytes": source_payload,
        "checked_source_bytes": checked,
        "source_structural_log": source_log,
        "source_recheck_log": _recheck(),
        "target_payload_bytes": json.dumps(target_payload).encode(),
        "target_structural_log": target_log,
        "source_support_olean": source_olean,
        "target_support_olean": target_olean,
        "checker_binary_bytes": checker,
    }


def _rebind_target_native_log(args: dict) -> None:
    """Keep the synthetic target claim envelope bound to the changed log.

    Tests mutate the *native observer* while preserving the upstream hash
    contract, so they reach the observer-specific fail-closed checks.
    """
    payload = json.loads(args["target_payload_bytes"])
    payload["target_native_preoracle_log_sha256"] = hashlib.sha256(
        args["target_structural_log"].encode()
    ).hexdigest()
    args["target_payload_bytes"] = json.dumps(payload).encode()



@pytest.mark.parametrize("change", ["none", "unrelated"])
def test_candidate_only_for_observed_transitive_identity(monkeypatch, change):
    row = m.evaluate_native_transitive_boundary(
        **_case(monkeypatch, unrelated=(change == "unrelated"))
    )
    assert row["decision"] == "CONDITIONAL_TRANSITIVE_CANDIDATE"
    assert row["observed_reference_names"] == ["Eq.refl", "Nat", "base", "op"]
    assert row["observed_base_ast_identical"] is True
    assert row["actual_kernel_transport_preservation_proved"] is False
    assert row["production_reliance_authorization"] is False
    assert row["target_historical_proof_replayed"] is False
    if change == "unrelated":
        assert row["baseline_identity_decision"] == "REVALIDATION_REQUIRED"


def test_changed_transitive_definition_detected_even_if_op_identical(monkeypatch):
    row = m.evaluate_native_transitive_boundary(
        **_case(monkeypatch, changed_base=True)
    )
    assert row["decision"] == "REVALIDATION_REQUIRED"
    assert row["reason_code"] == "transitive_base_drift"
    assert row["observed_op_ast_identical"] is True
    assert row["observed_base_ast_identical"] is False


def test_changed_direct_definition_detected(monkeypatch):
    row = m.evaluate_native_transitive_boundary(**_case(monkeypatch, changed_op=True))
    assert row["decision"] == "REVALIDATION_REQUIRED"
    assert row["reason_code"] == "op_declaration_drift"


def test_missing_second_native_observer_fails_closed(monkeypatch):
    with pytest.raises(ValueError, match="transitive native record"):
        m.evaluate_native_transitive_boundary(
            **_case(monkeypatch, omit_extra=True)
        )


def test_duplicate_native_observer_fails_closed(monkeypatch):
    args = _case(monkeypatch)
    line = args["target_structural_log"].splitlines()[-1]
    args["target_structural_log"] += "\n" + line
    _rebind_target_native_log(args)
    with pytest.raises(ValueError, match="transitive native record"):
        m.evaluate_native_transitive_boundary(**args)


def test_claimed_completeness_and_authority_rejected(monkeypatch):
    for key in ("support_completeness_proved", "relying_authority",
                "historical_certificate_replayed"):
        args = _case(monkeypatch)
        entries = args["target_structural_log"].splitlines()
        row = json.loads(entries[-1].partition(m._MARKER)[2])
        row[key] = True
        args["target_structural_log"] = (
            entries[0] + "\n" + m._MARKER + json.dumps(row)
        )
        _rebind_target_native_log(args)
        with pytest.raises(ValueError, match="unsupported authority"):
            m.evaluate_native_transitive_boundary(**args)


def test_native_observer_disagreement_rejected(monkeypatch):
    args = _case(monkeypatch)
    entries = args["target_structural_log"].splitlines()
    row = json.loads(entries[-1].partition(m._MARKER)[2])
    row["op_value_ast"] = _const("Nat")
    args["target_structural_log"] = (
        entries[0] + "\n" + m._MARKER + json.dumps(row)
    )
    _rebind_target_native_log(args)
    with pytest.raises(ValueError, match="two native observations"):
        m.evaluate_native_transitive_boundary(**args)


def test_transitive_record_malformed_json_rejected():
    with pytest.raises(ValueError, match="malformed"):
        m._native_record("RTK_TRANSITIVE_DECLARATION_JSON={bad")


def test_unknown_reference_is_not_admitted(monkeypatch):
    args = _case(monkeypatch)
    entries = args["target_structural_log"].splitlines()
    row = json.loads(entries[-1].partition(m._MARKER)[2])
    # A target-only reference in the base must be identical to the source
    # to reach the support classifier; otherwise it triggers revalidation.
    row["base_value_ast"] = _const("new_dependency")
    args["target_structural_log"] = (
        entries[0] + "\n" + m._MARKER + json.dumps(row)
    )
    _rebind_target_native_log(args)
    result = m.evaluate_native_transitive_boundary(**args)
    assert result["decision"] == "REVALIDATION_REQUIRED"
    assert result["production_reliance_authorization"] is False
