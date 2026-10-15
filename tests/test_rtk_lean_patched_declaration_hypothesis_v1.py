"""Synthetic adversarial tests; native validity is checked only in hosted Lean CI."""
import hashlib
import json

import pytest

from experiments.rtk.lean_historical_target_oracle_v1 import export_target_claim
from experiments.rtk.lean_patched_historical_certificate_v1 import export_source
from experiments.rtk import lean_patched_declaration_hypothesis_v1 as m
from experiments.rtk import lean_patched_preoracle_identity_v1 as identity


def _n(name: str) -> list:
    parent = ["anonymous"]
    for part in name.split("."):
        parent = ["str", parent, part]
    return parent


def _c(name: str) -> list:
    return ["const", _n(name), []]


def _native(*, target: bool = False, changed: bool = False,
            proof: list | None = None, op_name: str = "op") -> str:
    return "native: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "rtk_unproven_target_claim" if target else "historical_claim",
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": _c("op"),
        "theorem_value_ast": None if target else (proof or _c("Eq.refl")),
        "op_name": op_name,
        "op_type_ast": _c("Nat"),
        "op_value_ast": _c("Nat.add") if changed else _c("Nat"),
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    })


def _recheck(proof: list) -> str:
    return "native: RTK_SECOND_PROCESS_PROOF_JSON=" + json.dumps({
        "schema_version": "rtk.lean_second_process_kernel_check.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": _c("op"),
        "proof_ast": proof,
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


def _case(monkeypatch, *, changed=False, rebuilt=False, unrelated=False,
          proof=None):
    binary = b"synthetic-patched-checker"
    monkeypatch.setattr(
        identity, "_EXPECTED_LEAN_SHA", hashlib.sha256(binary).hexdigest()
    )
    proof = proof or _c("Eq.refl")
    checked_source = (
        b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n\n"
    )
    source_log = _native(proof=proof)
    source_payload = export_source(source_log, checked_source)
    target_log = _native(target=True, changed=changed)
    target_payload = export_target_claim(
        source_payload_bytes=source_payload, target_native_log=target_log
    )
    old_bytes = b"source module"
    new_bytes = (
        b"changed module" if changed else
        b"rebuilt module" if rebuilt else
        b"unrelated new declaration" if unrelated else
        old_bytes
    )
    return {
        "source_payload_bytes": source_payload,
        "checked_source_bytes": checked_source,
        "source_structural_log": source_log,
        "source_recheck_log": _recheck(proof),
        "target_payload_bytes": json.dumps(target_payload).encode(),
        "target_structural_log": target_log,
        "source_support_olean": old_bytes,
        "target_support_olean": new_bytes,
        "checker_binary_bytes": binary,
    }


@pytest.mark.parametrize("variant", ["same", "rebuilt", "unrelated"])
def test_declaration_candidate_ignores_whole_module_changes(monkeypatch, variant):
    kwargs = {variant: True} if variant != "same" else {}
    row = m.evaluate_declaration_hypothesis(**_case(monkeypatch, **kwargs))
    assert row["decision"] == "CONDITIONAL_DECLARATION_CANDIDATE"
    assert row["baseline_identity_decision"] == (
        "CONDITIONAL_IDENTITY_CANDIDATE" if variant == "same"
        else "REVALIDATION_REQUIRED"
    )
    assert row["production_reliance_authorization"] is False
    assert row["actual_kernel_support_preservation_proved"] is False
    assert row["reference_allowlist_is_complete_kernel_support"] is False
    assert row["target_historical_proof_replayed"] is False
    assert row["inspected_direct_reference_names"] == ["Eq.refl", "Nat", "op"]


def test_imported_definition_drift_forces_revalidation(monkeypatch):
    row = m.evaluate_declaration_hypothesis(**_case(monkeypatch, changed=True))
    assert row["decision"] == "REVALIDATION_REQUIRED"
    assert row["inspected_direct_reference_names"] == []
    assert row["target_claim_established"] is False


def test_unaccounted_historical_proof_reference_is_unresolved(monkeypatch):
    row = m.evaluate_declaration_hypothesis(
        **_case(monkeypatch, proof=_c("UnsafeImportedProof"))
    )
    assert row["decision"] == "UNRESOLVED"
    assert row["production_reliance_authorization"] is False


@pytest.mark.parametrize("node", [
    ["proj", _n("Nat"), 0, _c("op")],
    ["mvar", 0],
    ["letE", _n("a"), _c("Nat"), _c("Nat"), _c("Nat"), False],
])
def test_unsupported_expression_constructs_are_rejected(node):
    with pytest.raises(ValueError):
        m._references(node, remaining=[100])


def test_unknown_universe_instantiation_rejected():
    with pytest.raises(ValueError):
        m._references(["const", _n("Eq.refl"), [["param", _n("u")]]],
                      remaining=[100])


def test_bounded_reference_traversal():
    with pytest.raises(ValueError, match="budget"):
        m._references(["app", _c("op"), _c("Nat")], remaining=[1])


def test_native_source_recheck_cannot_be_omitted(monkeypatch):
    args = _case(monkeypatch)
    args["source_recheck_log"] = ""
    with pytest.raises(ValueError):
        m.evaluate_declaration_hypothesis(**args)


def test_native_target_payload_binding_cannot_be_forged(monkeypatch):
    args = _case(monkeypatch)
    args["target_structural_log"] = _native(target=True) + "\nforged"
    with pytest.raises(ValueError):
        m.evaluate_declaration_hypothesis(**args)


def test_equal_module_bytes_with_inconsistent_native_definition_rejected(monkeypatch):
    args = _case(monkeypatch, changed=True)
    args["target_support_olean"] = args["source_support_olean"]
    with pytest.raises(ValueError, match="contradictory definition AST"):
        m.evaluate_declaration_hypothesis(**args)
