"""Adversarial checks for the zero-trust observation binding protocol."""

import hashlib
import json

import pytest

from experiments.rtk.lean_structural_expr_v1 import _canonical, _digest
from experiments.rtk.lean_trust_zero_receipt_v1 import observe_trust_zero

EXPR = ["const", ["str", ["anonymous"], "op"], []]


def _make(tmp_path):
    roots = [tmp_path / "source", tmp_path / "target"]
    for root in roots:
        for name, value in [("Init.Prelude", b"prelude"), ("RTKSemanticSupport", b"definition")]:
            p = root / "lib" / "lean" / (name.replace(".", "/") + ".olean")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(value)
    source = _canonical({
        "schema_version": "rtk.lean_separate_source_proof_payload.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": EXPR, "proof_ast": EXPR,
        "source_native_log_sha256": "a" * 64,
        "source_checked_file_sha256": "b" * 64,
        "source_proof_expr_ast_sha256": _digest(EXPR),
        "historical_transport_applicability": "UNDETERMINED",
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False, "reliance_authorization": False,
    })
    def header(root, kind, trust):
        return "native: RTK_NATIVE_KERNEL_HEADER_JSON=" + json.dumps({
            "schema_version": "rtk.lean_native_kernel_header.v1-development",
            "root_name": root, "root_kind": kind, "trust_level": trust,
            "quotient_initialized": True,
            "target_historical_proof_replayed": False,
            "native_header_complete_environment_proof": False,
            "reliance_authorization": False,
        })
    return dict(
        source_payload_bytes=source,
        checked_source_witness={
            "serialized_payload_sha256": hashlib.sha256(source).hexdigest(),
            "source_checked_proof_ast_sha256": _digest(EXPR),
            "source_claim_ast_sha256": _digest(EXPR),
            "separate_process_native_source_proof_type_checked": True,
            "native_source_proof_type_matches_serialized_claim": True,
            "historical_theorem_not_in_new_environment": True,
            "target_historical_proof_replayed": False,
            "target_claim_established": False,
            "complete_semantic_support_proved": False,
            "reliance_authorization": False,
        },
        source_header_log=header("historical_claim", "theorem", 0),
        target_header_log=header("rtk_unproven_target_claim", "axiom", 0),
        target_structural_log="native: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps({
            "schema_version": "rtk.lean_native_structural_expr.v1-development",
            "theorem_name": "rtk_unproven_target_claim",
            "theorem_kind": "axiom", "theorem_type_ast": EXPR,
            "theorem_value_ast": None, "op_name": "op",
            "op_type_ast": EXPR, "op_value_ast": EXPR,
            "unsupported_constructs_silently_omitted": False,
            "imported_support_closure_proved": False,
        }),
        source_reference_log="native: RTK_NATIVE_REFERENCE_JSON=" +
            json.dumps({"environment_modules": ["Init.Prelude", "RTKSemanticSupport"]}),
        target_reference_log="native: RTK_NATIVE_REFERENCE_JSON=" +
            json.dumps({"environment_modules": ["Init.Prelude", "RTKSemanticSupport"]}),
        source_root=roots[0], target_root=roots[1],
    )


def test_recheck_binding_only_development(tmp_path):
    r = observe_trust_zero(**_make(tmp_path))
    assert r["source_proof_kernel_checked_under_trust_zero"] is True
    assert r["changed_imported_modules"] == []
    assert r["production_reliance_authorized"] is False
    assert r["semantic_support_complete_proved"] is False


def test_imported_module_drift_observed(tmp_path):
    case = _make(tmp_path)
    p = case["target_root"] / "lib/lean/RTKSemanticSupport.olean"
    p.write_bytes(b"different")
    assert observe_trust_zero(**case)["changed_imported_modules"] == ["RTKSemanticSupport"]


@pytest.mark.parametrize("side", ["source_header_log", "target_header_log"])
def test_default_trust_denied(tmp_path, side):
    case = _make(tmp_path)
    case[side] = case[side].replace('"trust_level": 0', '"trust_level": 1025')
    with pytest.raises(ValueError, match="trust zero"):
        observe_trust_zero(**case)


def test_wrong_historical_certificate_digest_denied(tmp_path):
    case = _make(tmp_path)
    case["checked_source_witness"]["serialized_payload_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="exact source certificate"):
        observe_trust_zero(**case)


def test_fresh_target_proof_not_admissible_as_unproved_claim(tmp_path):
    case = _make(tmp_path)
    case["target_structural_log"] = case["target_structural_log"].replace(
        '"theorem_kind": "axiom"', '"theorem_kind": "theorem"',
    )
    with pytest.raises(ValueError, match="source theorem|unexpected"):
        observe_trust_zero(**case)


def test_target_statement_substitution_denied(tmp_path):
    case = _make(tmp_path)
    case["target_structural_log"] = case["target_structural_log"].replace(
        '"theorem_type_ast": ' + json.dumps(EXPR),
        '"theorem_type_ast": ["natVal", 5]',
    )
    with pytest.raises(ValueError, match="claim differs"):
        observe_trust_zero(**case)


def test_missing_import_rejected(tmp_path):
    case = _make(tmp_path)
    (case["target_root"] / "lib/lean/RTKSemanticSupport.olean").unlink()
    with pytest.raises(ValueError, match="missing or redirected"):
        observe_trust_zero(**case)


def test_duplicate_native_header_denied(tmp_path):
    case = _make(tmp_path)
    case["source_header_log"] += "\n" + case["source_header_log"]
    with pytest.raises(ValueError, match="one native kernel-header"):
        observe_trust_zero(**case)


def test_incomplete_import_inventory_denied(tmp_path):
    case = _make(tmp_path)
    case["target_reference_log"] = "RTK_NATIVE_REFERENCE_JSON=" + json.dumps(
        {"environment_modules": ["Init.Prelude"]}
    )
    with pytest.raises(ValueError, match="inventory differs"):
        observe_trust_zero(**case)
