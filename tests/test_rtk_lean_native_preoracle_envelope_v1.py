"""Adversarial development tests for the pre-oracle native evidence join.

The synthetic fixture records are not native Lean outputs. A separate CI
workflow checks the same join on real native Lean 4.14.0 observations.
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from experiments.rtk.lean_native_preoracle_envelope_v1 import (
    bind_preoracle_native_evidence,
)
from experiments.rtk.lean_native_support_projection import project_native_probe
from experiments.rtk.lean_structural_expr_v1 import analyze_structural_pair

HIST = b"  Eq.refl n\n"
MODULES = ["Init.Prelude", "RTKSemanticSupport"]
O_TYPE = ["const", ["str", ["anonymous"], "Nat"], []]
O_SOURCE = ["lam", ["str", ["anonymous"], "n"], O_TYPE, ["bvar", 0], "default"]
O_TARGET = ["lam", ["str", ["anonymous"], "n"], O_TYPE, ["natVal", 0], "default"]
STMT = ["forallE", ["str", ["anonymous"], "n"], O_TYPE, O_TYPE, "default"]


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha_obj(value: object) -> str:
    return _sha_bytes(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode())


def _source_support() -> dict:
    return {
        "schema_version": "rtk.lean_native_support_probe.v1-development",
        "root": "historical_claim",
        "imported_boundary_expansion_complete": False,
        "items": [
            {"symbol": "historical_claim", "kind": "theorem",
             "expanded": True, "imported_module": "", "type_repr": "Nat theorem",
             "value_repr": "Eq.refl n", "references": ["op", "Eq.refl"]},
            {"symbol": "op", "kind": "definition",
             "expanded": False, "imported_module": "RTKSemanticSupport",
             "type_repr": "", "value_repr": "", "references": []},
            {"symbol": "Eq.refl", "kind": "constructor",
             "expanded": False, "imported_module": "Init.Prelude",
             "type_repr": "", "value_repr": "", "references": []},
        ],
    }


def _goal_support() -> dict:
    return {
        "schema_version": "rtk.lean_native_support_probe.v1-development",
        "root": "rtk_unproven_target_claim",
        "imported_boundary_expansion_complete": False,
        "items": [
            {"symbol": "rtk_unproven_target_claim", "kind": "axiom",
             "expanded": True, "imported_module": "", "type_repr": "Nat theorem",
             "value_repr": "", "references": ["op"]},
            {"symbol": "op", "kind": "definition",
             "expanded": False, "imported_module": "RTKSemanticSupport",
             "type_repr": "", "value_repr": "", "references": []},
        ],
    }


def _support_log(value: dict) -> str:
    return "file: info: RTK_NATIVE_SUPPORT_JSON=" + json.dumps(value)


def _refs_log() -> str:
    record = {
        "schema_version": "rtk.lean_imported_ref_lookup.v1-development",
        "environment_modules": MODULES,
        "items": [
            {"symbol": "op", "module": "RTKSemanticSupport",
             "kind": "definition", "type_repr": "Nat -> Nat"},
            {"symbol": "Eq.refl", "module": "Init.Prelude",
             "kind": "constructor", "type_repr": "Eq"},
        ],
    }
    return "file: info: RTK_NATIVE_REFERENCE_JSON=" + json.dumps(record)


def _structural_log(*, target=False, drift=True) -> str:
    record = {
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": (
            "rtk_unproven_target_claim" if target else "historical_claim"
        ),
        "theorem_kind": "axiom" if target else "theorem",
        "theorem_type_ast": STMT,
        "theorem_value_ast": None if target else [
            "const", ["str", ["anonymous"], "Eq.refl"], []
        ],
        "op_name": "op",
        "op_type_ast": O_TYPE,
        "op_value_ast": (
            O_TARGET if target and drift else O_SOURCE
        ),
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    }
    return "file: info: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(record)


def _module_records(*, drift=True):
    src = {
        module: {
            "relative_path": "lib/lean/" + module.replace(".", "/") + ".olean",
            "file_sha256": "a" * 64 if module == "Init.Prelude" else "b" * 64,
            "file_size_bytes": 80 if module == "Init.Prelude" else 30,
        } for module in MODULES
    }
    dst = copy.deepcopy(src)
    if drift:
        dst["RTKSemanticSupport"]["file_sha256"] = "c" * 64
    return src, dst


def _input(*, drift=True):
    source_native = _support_log(_source_support())
    goal_native = _support_log(_goal_support())
    refs = _refs_log()
    source_struct = _structural_log()
    target_struct = _structural_log(target=True, drift=drift)
    structural = analyze_structural_pair(source_struct, target_struct)
    source_modules, target_modules = _module_records(drift=drift)
    environment = {
        "schema_version": "rtk.lean_dual_installed_environment.v1-development",
        "source_toolchain_root": "/temp/source",
        "target_toolchain_root": "/temp/target",
        "separate_executable_paths_and_inodes_verified": True,
        "checker_binary_sha256":
            "eacf754d25ae86ea076882a34b9444f2485659d9df4266b821443b28ca95a215",
        "source_loaded_module_count": len(source_modules),
        "target_loaded_module_count": len(target_modules),
        "source_loaded_bytes": sum(r["file_size_bytes"] for r in source_modules.values()),
        "target_loaded_bytes": sum(r["file_size_bytes"] for r in target_modules.values()),
        "source_module_inventory_sha256": _sha_obj(source_modules),
        "target_module_inventory_sha256": _sha_obj(target_modules),
        "source_modules": source_modules,
        "target_modules": target_modules,
        "source_only_modules": [],
        "target_only_modules": [],
        "changed_module_bytes": ["RTKSemanticSupport"] if drift else [],
        "old_proof_reference_differences": [],
        "old_proof_reference_count": 2,
        "environment_byte_comparison": "DRIFT_DETECTED" if drift else "BYTE_IDENTICAL",
        "source_native_log_sha256": _sha_bytes(source_native.encode()),
        "source_refs_log_sha256": _sha_bytes(refs.encode()),
        "target_refs_log_sha256": _sha_bytes(refs.encode()),
        "target_goal_log_sha256": _sha_bytes(goal_native.encode()),
        "target_goal_native_projection_sha256":
            project_native_probe(_goal_support())["source_probe_sha256"],
        "target_goal_is_unproved_axiom_placeholder": True,
        "independently_administered_builds_verified": False,
        "module_dependency_semantic_closure_proved": False,
        "cross_version_compatibility_proved": False,
        "historical_proof_replayed_on_target": False,
        "fresh_target_proof_supplied": False,
        "target_claim_established": False,
        "native_transport_oracle_executed": False,
        "transport_applicability": "UNDETERMINED",
        "reliance_authorization": False,
    }
    return {
        "environment": environment,
        "structural": structural,
        "source_native_log": source_native,
        "source_reference_log": refs,
        "target_reference_log": refs,
        "target_unproved_goal_log": goal_native,
        "source_structural_log": source_struct,
        "target_structural_log": target_struct,
        "historical_proof_source": HIST,
    }


def test_native_join_revalidates_realistic_semantic_drift_and_never_valid():
    result = bind_preoracle_native_evidence(**_input())
    assert result["changed_imported_module_bytes"] == ["RTKSemanticSupport"]
    assert result["conservative_action"] == "REVALIDATION_REQUIRED"
    assert result["historical_evidence_applicability"] == "UNDETERMINED"
    assert result["native_evidence_internal_integrity_checked"] is True
    assert result["independent_runner_attestation_verified"] is False
    assert result["complete_semantic_support_established"] is False
    assert result["reliance_authorization"] is False


def test_no_observed_drift_still_abstains():
    result = bind_preoracle_native_evidence(**_input(drift=False))
    assert result["conservative_action"] == "UNRESOLVED"
    assert result["historical_evidence_applicability"] == "UNDETERMINED"


@pytest.mark.parametrize(
    ("modify", "reason"),
    [
        (lambda x: x["environment"].update({
            "source_module_inventory_sha256": "0" * 64
        }), "inventory count/digest"),
        (lambda x: x["environment"].update({
            "changed_module_bytes": []
        }), "module drift contradicts"),
        (lambda x: x["environment"].update({
            "target_claim_established": True
        }), "oracle contamination"),
        (lambda x: x["environment"].update({
            "native_transport_oracle_executed": True
        }), "oracle contamination"),
        (lambda x: x["environment"].update({
            "source_native_log_sha256": "0" * 64
        }), "native log bytes"),
        (lambda x: x["environment"].update({
            "source_toolchain_root": "/temp/target"
        }), "distinct toolchain"),
        (lambda x: x["environment"].update({
            "surprise_oracle_result": "INADMISSIBLE"
        }), "evidence schema"),
        (lambda x: x["structural"].update({
            "target_claim_established": True
        }), "structural AST evidence"),
        (lambda x: x["environment"].update({
            "old_proof_reference_count": 1
        }), "proof-reference observation"),
    ],
)
def test_altered_native_envelope_fails_closed(modify, reason):
    data = _input()
    modify(data)
    with pytest.raises(ValueError, match=reason):
        bind_preoracle_native_evidence(**data)


def test_substituting_source_proof_log_fails_closed():
    case = _input()
    case["source_native_log"] = case["source_native_log"].replace(
        "Eq.refl", "Nonexistent"
    )
    with pytest.raises(ValueError, match="native log bytes"):
        bind_preoracle_native_evidence(**case)


def test_unknown_target_proof_cannot_be_misreported_as_unproved():
    case = _input()
    goal = _goal_support()
    goal["items"][0]["value_repr"] = "old proof"
    case["target_unproved_goal_log"] = _support_log(goal)
    case["environment"]["target_goal_log_sha256"] = _sha_bytes(
        case["target_unproved_goal_log"].encode()
    )
    with pytest.raises(ValueError):
        bind_preoracle_native_evidence(**case)
