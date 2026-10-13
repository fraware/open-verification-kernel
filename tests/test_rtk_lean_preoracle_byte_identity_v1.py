"""Pre-oracle candidates: synthetic records with real module-byte comparisons.

Native Lean execution and the independent oracle are exercised in the pinned
development workflow. These tests never create an oracle-derived predictor.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.rtk.lean_historical_target_oracle_v1 import export_target_claim
from experiments.rtk.lean_native_preoracle_envelope_v1 import _modules
from experiments.rtk.lean_preoracle_byte_identity_v1 import (
    evaluate_preoracle_identity,
)
from experiments.rtk.lean_structural_expr_v1 import _canonical, _digest

_EXPR = ["const", ["str", ["anonymous"], "op"], []]


def _name(name: str) -> list:
    return ["str", ["anonymous"], name]


def _node(name: str, kind: str, module: str, refs: tuple[str, ...]) -> dict:
    return {
        "name": name, "name_ast": _name(name),
        "kind": kind, "module": module,
        "unsafe": False, "partial": False, "level_parameter_count": 0,
        "direct_references": list(refs),
        "direct_reference_asts": [_name(r) for r in refs],
    }


def _closure_graph(
    root: str, *, target: bool = False, local_dependency: bool = False,
    op_only: bool = False,
) -> dict:
    nodes = [
        _node("Nat", "inductive", "Init.Prelude", ()),
        _node("op", "definition", "RTKSemanticSupport", ("Nat",)),
    ]
    if local_dependency:
        nodes.append(_node("rtkLocal", "definition", "LOCAL", ("Nat",)))
    if not op_only:
        refs = ("op", "rtkLocal") if local_dependency else ("op",)
        nodes.append(_node(
            root, "axiom" if target else "theorem", "LOCAL", refs,
        ))
    if op_only:
        nodes = nodes[:2]
    return {
        "root_name": "op" if op_only else root,
        "root_name_ast": _name("op" if op_only else root),
        "node_count": len(nodes),
        "edge_count": sum(len(n["direct_references"]) for n in nodes),
        "nodes": nodes,
        "missing_references_rejected": True,
        "budget_exhaustion_rejected": True,
        "reported_reference_relation": "ConstantInfo.getUsedConstantsAsSet",
        "complete_for_reported_reference_relation_under_budget": True,
        "semantic_dependency_closure_proved": False,
    }


def _closure_log(*, target: bool = False, local_dependency: bool = False) -> str:
    root = "rtk_unproven_target_claim" if target else "historical_claim"
    record = {
        "schema_version": "rtk.lean_native_strict_decl_closure.v1-development",
        "root_name": root,
        "root_kind": "target_goal_placeholder" if target else "source_theorem",
        "root_declaration_closure": _closure_graph(
            root, target=target, local_dependency=local_dependency,
        ),
        "imported_definition_closure": _closure_graph(root, op_only=True),
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "axiom_policy_authenticated": False,
        "source_target_environment_authenticity_verified": False,
        "semantic_support_complete": False,
        "transport_applicability": "UNDETERMINED",
        "reliance_authorization": False,
    }
    return "native: RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(record)



def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _native_target() -> str:
    return "native: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "rtk_unproven_target_claim",
        "theorem_kind": "axiom",
        "theorem_type_ast": _EXPR,
        "theorem_value_ast": None,
        "op_name": "op", "op_type_ast": _EXPR, "op_value_ast": _EXPR,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    })


def _module(root: Path, name: str, content: bytes) -> dict:
    path = root / "lib" / "lean" / (name.replace(".", "/") + ".olean")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "relative_path": "lib/lean/" + name.replace(".", "/") + ".olean",
        "file_sha256": _sha(content),
        "file_size_bytes": len(content),
    }


def _fixture(tmp_path: Path, monkeypatch) -> dict:
    source_root = tmp_path / "source"
    target_root = tmp_path / "target"
    source_root.mkdir()
    target_root.mkdir()
    source_modules = {
        "Init.Prelude": _module(source_root, "Init.Prelude", b"prelude"),
        "RTKSemanticSupport": _module(source_root, "RTKSemanticSupport", b"op := n"),
    }
    for name, content in (
        ("Init.Prelude", b"prelude"), ("RTKSemanticSupport", b"op := n")
    ):
        _module(target_root, name, content)
    src, total, fingerprint = _modules(source_modules)
    source = _canonical({
        "schema_version": "rtk.lean_separate_source_proof_payload.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": _EXPR, "proof_ast": _EXPR,
        "source_native_log_sha256": "a" * 64,
        "source_checked_file_sha256": "b" * 64,
        "source_proof_expr_ast_sha256": _digest(_EXPR),
        "historical_transport_applicability": "UNDETERMINED",
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False, "reliance_authorization": False,
    })
    witness = {
        "separate_process_native_source_proof_type_checked": True,
        "native_source_proof_type_matches_serialized_claim": True,
        "historical_theorem_not_in_new_environment": True,
        "serialized_payload_sha256": _sha(source),
        "source_checked_proof_ast_sha256": _digest(_EXPR),
        "source_claim_ast_sha256": _digest(_EXPR),
        "source_checker_input_sha256": "b" * 64,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "complete_semantic_support_proved": False,
        "reliance_authorization": False,
    }
    target_native = _native_target()
    target = _canonical(export_target_claim(
        source_payload_bytes=source, target_native_log=target_native
    ))
    env = {
        "schema_version": "rtk.lean_dual_installed_environment.v1-development",
        "checker_binary_sha256":
            "eacf754d25ae86ea076882a34b9444f2485659d9df4266b821443b28ca95a215",
        "source_toolchain_root": str(source_root),
        "target_toolchain_root": str(target_root),
        "separate_executable_paths_and_inodes_verified": True,
        "source_modules": src, "target_modules": source_modules,
        "source_module_inventory_sha256": fingerprint,
        "source_loaded_bytes": total,
        "source_loaded_module_count": len(src),
        "independently_administered_builds_verified": False,
        "module_dependency_semantic_closure_proved": False,
        "historical_proof_replayed_on_target": False,
        "native_transport_oracle_executed": False,
        "target_claim_established": False,
        "reliance_authorization": False,
        "transport_applicability": "UNDETERMINED",
    }
    # Native end-to-end workflow separately checks the actual pinned binaries.
    # These synthetic Python tests retain true on-disk .olean byte comparison.
    monkeypatch.setattr(
        "experiments.rtk.lean_preoracle_byte_identity_v1._installed_root",
        lambda root, executable: root.resolve(),
    )
    (source_root / "lean").write_bytes(b"dummy")
    (target_root / "lean").write_bytes(b"dummy")
    return {
        "environment": env, "source_payload_bytes": source,
        "source_native_witness": witness, "target_payload_bytes": target,
        "target_structural_log": target_native,
        "current_target_reference_log": "RTK_NATIVE_REFERENCE_JSON=" + json.dumps({
            "environment_modules": sorted(source_modules),
        }),
        "source_declaration_closure_log": _closure_log(),
        "current_target_declaration_closure_log": _closure_log(target=True),
        "source_root": source_root, "target_root": target_root,
        "source_checker": source_root / "lean",
        "target_checker": target_root / "lean",
    }


def test_identical_full_native_loaded_inventory_only_conditional(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    result = evaluate_preoracle_identity(**case)
    assert result["decision"] == "CONDITIONAL_IDENTITY_CANDIDATE"
    assert result["candidate_for_reuse_under_explicit_unproved_premises"] is True
    assert result["target_historical_proof_replayed"] is False
    assert result["oracle_consulted"] is False
    assert result["production_reliance_authorization"] is False
    assert result["full_kernel_environment_equivalence_proved"] is False


def test_changed_loaded_definition_fails_conservative_reuse(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    _module(case["target_root"], "RTKSemanticSupport", b"op := 0 + n")
    result = evaluate_preoracle_identity(**case)
    assert result["decision"] == "REVALIDATION_REQUIRED"
    assert result["changed_imported_modules"] == ["RTKSemanticSupport"]
    assert result["candidate_for_reuse_under_explicit_unproved_premises"] is False


def test_unrelated_repository_edit_is_not_imported_semantic_drift(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    (case["target_root"] / "unrelated.txt").write_text("edit outside loaded context")
    assert evaluate_preoracle_identity(**case)["decision"] == (
        "CONDITIONAL_IDENTITY_CANDIDATE"
    )


def test_extra_native_loaded_module_is_unresolved(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    case["current_target_reference_log"] = "RTK_NATIVE_REFERENCE_JSON=" + (
        json.dumps({"environment_modules": [
            "Init.Prelude", "RTKSemanticSupport", "Unexpected.Module"
        ]})
    )
    result = evaluate_preoracle_identity(**case)
    assert result["decision"] == "UNRESOLVED"
    assert result["production_reliance_authorization"] is False


def test_missing_target_import_is_unresolved(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    path = case["target_root"] / "lib/lean/RTKSemanticSupport.olean"
    path.unlink()
    result = evaluate_preoracle_identity(**case)
    assert result["decision"] == "UNRESOLVED"
    assert result["reason_codes"] == ["target_import_acquisition_incomplete"]


def test_source_receipt_broken_is_rejected(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    case["source_native_witness"]["serialized_payload_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="source certificate not bound"):
        evaluate_preoracle_identity(**case)


def test_target_oracle_flag_leaks_are_rejected(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    case["environment"]["native_transport_oracle_executed"] = True
    with pytest.raises(ValueError, match="contaminated"):
        evaluate_preoracle_identity(**case)


def test_drift_in_source_receipted_module_is_rejected(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    _module(case["source_root"], "RTKSemanticSupport", b"tampered")
    with pytest.raises(ValueError, match="source imported module bytes changed"):
        evaluate_preoracle_identity(**case)


def test_target_claim_ast_tampering_is_rejected(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    target = json.loads(case["target_payload_bytes"])
    target["claim_ast"] = ["natVal", 0]
    case["target_payload_bytes"] = _canonical(target)
    with pytest.raises(ValueError, match="unproved native target claim"):
        evaluate_preoracle_identity(**case)


def test_authenticity_is_not_inferred_from_equal_hashes(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    out = evaluate_preoracle_identity(**case)
    assert out["external_policy_and_provenance_authenticated"] is False
    assert out["module_semantic_support_complete_proved"] is False
    assert out["production_reliance_authorization"] is False


def test_unchanged_olean_does_not_cover_source_local_definition(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    case["source_declaration_closure_log"] = _closure_log(local_dependency=True)
    result = evaluate_preoracle_identity(**case)
    assert result["decision"] == "UNRESOLVED"
    assert result["reason_codes"] == ["unaccounted_local_declaration_dependency"]
    assert result["candidate_for_reuse_under_explicit_unproved_premises"] is False


def test_unchanged_olean_does_not_cover_target_local_definition(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    case["current_target_declaration_closure_log"] = _closure_log(
        target=True, local_dependency=True,
    )
    result = evaluate_preoracle_identity(**case)
    assert result["decision"] == "UNRESOLVED"
    assert result["production_reliance_authorization"] is False


def test_missing_native_scope_is_rejected_even_with_equal_olean(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    case["source_declaration_closure_log"] = ""
    with pytest.raises(ValueError, match="one bounded native closure"):
        evaluate_preoracle_identity(**case)


def test_unsupported_root_dependency_graph_rejected(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    tag, text = case["source_declaration_closure_log"].split(
        "RTK_NATIVE_STRICT_CLOSURE_JSON=", 1
    )
    data = json.loads(text)
    root = data["root_declaration_closure"]
    root["nodes"] = [n for n in root["nodes"] if n["name"] != "op"]
    root["node_count"] -= 1
    root["edge_count"] -= 1
    case["source_declaration_closure_log"] = tag + (
        "RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(data)
    )
    with pytest.raises(ValueError, match="UNRESOLVED_REFERENCED_DECLARATION"):
        evaluate_preoracle_identity(**case)


def test_changed_module_still_requires_import_only_native_scope(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    _module(case["target_root"], "RTKSemanticSupport", b"op := 0 + n")
    case["current_target_declaration_closure_log"] = _closure_log(
        target=True, local_dependency=True,
    )
    out = evaluate_preoracle_identity(**case)
    assert out["decision"] == "UNRESOLVED"
    assert "unaccounted_local_declaration_dependency" in out["reason_codes"]


def test_imported_fragment_excludes_opaque_local_override(tmp_path, monkeypatch):
    case = _fixture(tmp_path, monkeypatch)
    tag, raw = case["current_target_declaration_closure_log"].split(
        "RTK_NATIVE_STRICT_CLOSURE_JSON=", 1
    )
    record = json.loads(raw)
    for g in ("root_declaration_closure", "imported_definition_closure"):
        for entry in record[g]["nodes"]:
            if entry["name"] == "op":
                entry["module"] = "LOCAL"
    case["current_target_declaration_closure_log"] = (
        tag + "RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(record)
    )
    assert evaluate_preoracle_identity(**case)["decision"] == "UNRESOLVED"
