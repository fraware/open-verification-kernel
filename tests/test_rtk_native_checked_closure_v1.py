"""Contract tests for bounded checked-declaration closure; no native oracle labels."""
from __future__ import annotations

import hashlib
import json

import pytest

from experiments.rtk import lean_native_checked_closure_v1 as closure
from experiments.rtk import lean_patched_preoracle_identity_v1 as identity
from experiments.rtk.lean_historical_target_oracle_v1 import export_target_claim
from experiments.rtk.lean_patched_historical_certificate_v1 import export_source


def const(name: str) -> list:
    cur = ["anonymous"]
    for part in name.split("."):
        cur = ["str", cur, part]
    return ["const", cur, []]


def node(name: str, value: str) -> dict:
    refs = sorted({"Nat", value})
    return {
        "name": name, "kind": "definition", "type_ast": const("Nat"),
        "value_ast": const(value), "level_params": [],
        "reducibility_hint": ["regular", 0], "safety": "safe",
        "direct_references": refs,
        "native_full_semantic_support_proved": False,
    }


def log(*, target: bool = False, drift: bool = False) -> str:
    proof = None if target else const("Eq.refl")
    struct = {
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "rtk_unproven_target_claim" if target else "historical_claim",
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": const("op"), "theorem_value_ast": proof,
        "op_name": "op", "op_type_ast": const("Nat"), "op_value_ast": const("base"),
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    }
    graph = {
        "schema_version": closure._SCHEMA,
        "root_name": "rtk_unproven_target_claim" if target else "historical_claim",
        "root_kind": "unproved_target_placeholder" if target else "historical_theorem",
        "root_type_references": ["op"],
        "root_proof_references": [] if target else ["Eq.refl"],
        "trusted_core_frontier": sorted(closure._BASE),
        "nodes": [
            node("op", "base"),
            node("base", "leaf"),
            node("leaf", "Nat.succ" if drift else "Nat"),
        ],
        "native_declaration_relation_exhaustive_for_kernel_proved": False,
        "core_frontier_semantics_authenticated": False,
        "historical_target_certificate_replayed": False,
        "relying_authorization": False,
    }
    return ("RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(struct)
            + "\n" + closure._MARKER + json.dumps(graph))


def recheck() -> str:
    d = {
        "schema_version": "rtk.lean_second_process_kernel_check.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": const("op"),
        "proof_ast": const("Eq.refl"),
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
    return "RTK_SECOND_PROCESS_PROOF_JSON=" + json.dumps(d)


def args(monkeypatch, *, changed=False, unrelated=False) -> dict:
    binary = b"synthetic-patched-binary"
    monkeypatch.setattr(
        identity, "_EXPECTED_LEAN_SHA", hashlib.sha256(binary).hexdigest()
    )
    checked = b"theorem historical_claim (n : Nat) : op n = n := Eq.refl n\n"
    s, t = log(), log(target=True, drift=changed)
    source = export_source(s, checked)
    target = export_target_claim(source_payload_bytes=source, target_native_log=t)
    return {
        "source_payload_bytes": source,
        "checked_source_bytes": checked,
        "source_structural_log": s,
        "source_recheck_log": recheck(),
        "target_payload_bytes": json.dumps(target).encode(),
        "target_structural_log": t,
        "source_support_olean": b"source",
        "target_support_olean": (
            b"changed" if changed else b"unrelated" if unrelated else b"source"
        ),
        "checker_binary_bytes": binary,
    }


def modify_target(data: dict, mutator) -> None:
    raw = data["target_structural_log"].splitlines()
    obj = json.loads(raw[-1].partition(closure._MARKER)[2])
    mutator(obj)
    data["target_structural_log"] = raw[0] + "\n" + closure._MARKER + json.dumps(obj)
    payload = json.loads(data["target_payload_bytes"])
    payload["target_native_preoracle_log_sha256"] = hashlib.sha256(
        data["target_structural_log"].encode()
    ).hexdigest()
    data["target_payload_bytes"] = json.dumps(payload).encode()


@pytest.mark.parametrize("unrelated", [False, True])
def test_complete_declared_graph_candidate(monkeypatch, unrelated):
    result = closure.evaluate_checked_closure(**args(monkeypatch, unrelated=unrelated))
    assert result["decision"] == "CONDITIONAL_CLOSED_REFERENCE_CANDIDATE"
    assert result["observed_closed_noncore_names"] == ["base", "leaf", "op"]
    assert result["kernel_semantic_dependency_completeness_proved"] is False
    assert result["production_reliance_authorization"] is False


def test_changed_third_level_decl_requires_revalidation(monkeypatch):
    result = closure.evaluate_checked_closure(**args(monkeypatch, changed=True))
    assert result["decision"] == "REVALIDATION_REQUIRED"
    assert result["changed_declaration_names"] == ["leaf"]


def test_missing_transitive_node_rejected(monkeypatch):
    data = args(monkeypatch)
    modify_target(data, lambda obj: obj["nodes"].pop())
    with pytest.raises(ValueError, match="missing non-core"):
        closure.evaluate_checked_closure(**data)


def test_forged_native_edge_rejected(monkeypatch):
    data = args(monkeypatch)
    modify_target(
        data, lambda obj: obj["nodes"][1].update({"direct_references": ["Nat"]})
    )
    with pytest.raises(ValueError, match="edges disagree"):
        closure.evaluate_checked_closure(**data)


def test_unreachable_native_node_rejected(monkeypatch):
    data = args(monkeypatch)
    def change(obj):
        extra = node("injected", "Nat")
        obj["nodes"].append(extra)
    modify_target(data, change)
    with pytest.raises(ValueError, match="extraneous or disconnected"):
        closure.evaluate_checked_closure(**data)


@pytest.mark.parametrize("attribute,value", [
    ("kind", "axiom"), ("safety", "unsafe"),
    ("native_full_semantic_support_proved", True),
])
def test_unsupported_declaration_metadata_rejected(monkeypatch, attribute, value):
    data = args(monkeypatch)
    modify_target(data, lambda obj: obj["nodes"][0].update({attribute: value}))
    with pytest.raises(ValueError, match="unsupported, duplicated"):
        closure.evaluate_checked_closure(**data)


def test_unknown_core_frontier_rejected(monkeypatch):
    data = args(monkeypatch)
    modify_target(data, lambda obj: obj["trusted_core_frontier"].append("Mystery"))
    with pytest.raises(ValueError, match="trusted core"):
        closure.evaluate_checked_closure(**data)


def test_duplicate_declaration_rejected(monkeypatch):
    data = args(monkeypatch)
    modify_target(data, lambda obj: obj["nodes"].append(obj["nodes"][0].copy()))
    with pytest.raises(ValueError, match="unsupported, duplicated"):
        closure.evaluate_checked_closure(**data)


def test_missing_native_graph_receipt_rejected(monkeypatch):
    data = args(monkeypatch)
    data["source_structural_log"] = data["source_structural_log"].splitlines()[0]
    with pytest.raises(ValueError):
        closure.evaluate_checked_closure(**data)
