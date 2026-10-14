"""Patched-Lean development receipts for re-exported historical proof and unproved targets.

This module makes NO replay-free soundness or reliance claim. It refuses to
reuse Lean 4.14.0 payloads: the source proof is natively extracted again on
the patched checker, then byte-identified and sealed before the target oracle.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from experiments.rtk.lean_historical_target_oracle_v1 import (
    _source, export_target_claim,
)
from experiments.rtk.lean_structural_expr_v1 import (
    _canonical, _digest, _structural_ast,
)

_VERSION = "4.35.0"
_SCHEMA = "rtk.lean_patched_historical_preoracle.v1-development"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reexport_source(native_log: str, checked_source_bytes: bytes) -> bytes:
    """Export source proof from patched native theorem, never from legacy JSON."""
    record = _structural_ast(native_log)
    if record["theorem_name"] != "historical_claim" or (
        record["theorem_kind"] != "theorem"
        or record["theorem_value_ast"] is None
    ):
        raise ValueError("patched source must be checked historical theorem")
    payload = {
        "schema_version": "rtk.lean_separate_source_proof_payload.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": record["theorem_type_ast"],
        "proof_ast": record["theorem_value_ast"],
        "source_native_log_sha256": digest(native_log.encode()),
        "source_checked_file_sha256": digest(checked_source_bytes),
        "source_proof_expr_ast_sha256": _digest(record["theorem_value_ast"]),
        "historical_transport_applicability": "UNDETERMINED",
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False,
        "reliance_authorization": False,
    }
    raw = _canonical(payload) + b"\n"
    _source(raw)
    return raw


def seal_patched_contexts(
    *,
    historical_source_payload: bytes,
    source_structural_log: str,
    target_equal_log: str,
    target_changed_log: str,
    checker_binary_sha256: str,
    source_module: bytes,
    target_equal_module: bytes,
    target_changed_module: bytes,
) -> dict[str, Any]:
    """Compare only *observations* made before any historical target replay."""
    source = _source(historical_source_payload)
    actual = _structural_ast(source_structural_log)
    if actual["theorem_name"] != "historical_claim" or (
        actual["theorem_kind"] != "theorem"
        or actual["theorem_type_ast"] != source["claim_ast"]
        or actual["theorem_value_ast"] != source["proof_ast"]
    ):
        raise ValueError("patched source certificate does not match native record")
    if digest(source_structural_log.encode()) != source["source_native_log_sha256"]:
        raise ValueError("source transcript was substituted")
    records = {
        "equal": _structural_ast(target_equal_log),
        "changed": _structural_ast(target_changed_log),
    }
    target_payloads = {}
    for kind, log in (("equal", target_equal_log), ("changed", target_changed_log)):
        r = records[kind]
        if r["theorem_name"] != "rtk_unproven_target_claim" or (
            r["theorem_kind"] != "axiom" or r["theorem_value_ast"] is not None
        ):
            raise ValueError("patched target has a proof, wrong name, or wrong kind")
        target_payloads[kind] = export_target_claim(
            source_payload_bytes=historical_source_payload,
            target_native_log=log,
        )
    if records["equal"]["op_value_ast"] != actual["op_value_ast"]:
        raise ValueError("equal target unexpectedly changes imported definition")
    if records["changed"]["op_value_ast"] == actual["op_value_ast"]:
        raise ValueError("changed target has no observed semantic definition drift")
    if records["equal"]["op_type_ast"] != records["changed"]["op_type_ast"]:
        raise ValueError("target imported declaration types differ")
    if any(not m for m in (
        source_module, target_equal_module, target_changed_module,
    )):
        raise ValueError("empty rebuilt patched module")
    if not isinstance(checker_binary_sha256, str) or (
        len(checker_binary_sha256) != 64
        or any(c not in "0123456789abcdef" for c in checker_binary_sha256)
    ):
        raise ValueError("invalid patched executable fingerprint")
    return {
        "schema_version": _SCHEMA,
        "checker_version": _VERSION,
        "checker_binary_sha256": checker_binary_sha256,
        "source_payload_sha256": digest(historical_source_payload),
        "source_proof_ast_sha256": _digest(source["proof_ast"]),
        "source_claim_ast_sha256": _digest(source["claim_ast"]),
        "target_equal_native_log_sha256": digest(target_equal_log.encode()),
        "target_changed_native_log_sha256": digest(target_changed_log.encode()),
        "source_olean_sha256": digest(source_module),
        "target_equal_olean_sha256": digest(target_equal_module),
        "target_changed_olean_sha256": digest(target_changed_module),
        "identical_structural_claims_observed": True,
        "equal_imported_definition_ast_observed": True,
        "changed_imported_definition_ast_observed": True,
        "source_proof_reexported_under_patched_lean": True,
        "target_claims_unproved_before_oracle": True,
        "historical_target_replay_executed": False,
        "kernel_context_equivalence_proved": False,
        "transport_support_soundness_proved": False,
        "provenance_policy_authenticated": False,
        "independent_checker_source_theorem_checked": False,
        "production_reliance_authorized": False,
    }


def write_new(path, record: dict[str, Any]) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(record) + b"\n")


def require_sealed_before_oracle(
    manifest: dict[str, Any], source_payload: bytes,
    equal_log: str, changed_log: str,
) -> None:
    if set(manifest) != {
        "schema_version", "checker_version", "checker_binary_sha256",
        "source_payload_sha256", "source_proof_ast_sha256",
        "source_claim_ast_sha256", "target_equal_native_log_sha256",
        "target_changed_native_log_sha256", "source_olean_sha256",
        "target_equal_olean_sha256", "target_changed_olean_sha256",
        "identical_structural_claims_observed",
        "equal_imported_definition_ast_observed",
        "changed_imported_definition_ast_observed",
        "source_proof_reexported_under_patched_lean",
        "target_claims_unproved_before_oracle",
        "historical_target_replay_executed",
        "kernel_context_equivalence_proved",
        "transport_support_soundness_proved",
        "provenance_policy_authenticated",
        "independent_checker_source_theorem_checked",
        "production_reliance_authorized",
    }:
        raise ValueError("patched sealed manifest schema mismatch")
    if manifest["schema_version"] != _SCHEMA or (
        manifest["checker_version"] != _VERSION
        or manifest["source_payload_sha256"] != digest(source_payload)
        or manifest["target_equal_native_log_sha256"] != digest(equal_log.encode())
        or manifest["target_changed_native_log_sha256"] != digest(changed_log.encode())
        or any(manifest[k] is not True for k in (
            "identical_structural_claims_observed",
            "equal_imported_definition_ast_observed",
            "changed_imported_definition_ast_observed",
            "source_proof_reexported_under_patched_lean",
            "target_claims_unproved_before_oracle",
        ))
        or any(manifest[k] is not False for k in (
            "historical_target_replay_executed",
            "kernel_context_equivalence_proved",
            "transport_support_soundness_proved",
            "provenance_policy_authenticated",
            "independent_checker_source_theorem_checked",
            "production_reliance_authorized",
        ))
    ):
        raise ValueError("contaminated patched manifest or altered preoracle evidence")
