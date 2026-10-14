"""Pre-oracle, non-controlling identity screen for patched Lean 4.35.

The function deliberately receives no target replay log, decision, proof, or
oracle callback. Its strongest output is CONDITIONAL_IDENTITY_CANDIDATE;
the historical target certificate is adjudicated *later* by another process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_historical_target_oracle_v1 import _source
from experiments.rtk.lean_structural_expr_v1 import _digest, _structural_ast

_EXPECTED_LEAN_SHA = "bf8d54e4714cc4b03d3f6bb34c83b7202b87e49c8bfcbff6895c085bb90ceb38"
_SCHEMA = "rtk.lean_patched_preoracle_identity.v1-development"
_SOURCE_MARKER = "RTK_SECOND_PROCESS_PROOF_JSON="


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _one_record(log: str, marker: str) -> dict[str, Any]:
    entries = [line.partition(marker)[2].strip()
               for line in log.splitlines() if marker in line]
    if len(entries) != 1 or len(entries[0]) > 1_000_000:
        raise ValueError("one bounded native evidence marker required")
    try:
        record = json.loads(entries[0])
    except ValueError as error:
        raise ValueError("invalid native evidence JSON") from error
    if not isinstance(record, dict):
        raise ValueError("native evidence is not an object")
    return record


def _native_source_rechecked(
    *, native_log: str, source: dict[str, Any],
) -> None:
    evidence = _one_record(native_log, _SOURCE_MARKER)
    expected_keys = {
        "schema_version", "declaration_name", "claim_ast", "proof_ast",
        "source_proof_kernel_checked",
        "source_proof_type_defeq_serialized_claim",
        "historical_theorem_not_imported_or_declared",
        "serialized_expr_loaded_from_disk", "independent_process_from_serializer",
        "target_historical_proof_replayed", "target_claim_established",
        "independently_governed_provenance",
        "transitive_support_completeness_proved",
        "transport_applicability_established",
    }
    if (
        set(evidence) != expected_keys
        or evidence["schema_version"]
        != "rtk.lean_second_process_kernel_check.v1-development"
        or evidence["declaration_name"] != "historical_claim"
        or evidence["claim_ast"] != source["claim_ast"]
        or evidence["proof_ast"] != source["proof_ast"]
        or any(evidence[k] is not True for k in (
            "source_proof_kernel_checked",
            "source_proof_type_defeq_serialized_claim",
            "historical_theorem_not_imported_or_declared",
            "serialized_expr_loaded_from_disk",
            "independent_process_from_serializer",
        ))
        or any(evidence[k] is not False for k in (
            "target_historical_proof_replayed",
            "target_claim_established",
            "independently_governed_provenance",
            "transitive_support_completeness_proved",
            "transport_applicability_established",
        ))
    ):
        raise ValueError("source proof native witness missing or contaminated")


def _target_record(
    *, native_log: str, target_payload_bytes: bytes, source_payload_bytes: bytes,
    source: dict[str, Any],
) -> dict[str, Any]:
    observed = _structural_ast(native_log)
    if (
        observed["theorem_name"] != "rtk_unproven_target_claim"
        or observed["theorem_kind"] != "axiom"
        or observed["theorem_value_ast"] is not None
        or observed["theorem_type_ast"] != source["claim_ast"]
    ):
        raise ValueError("target is not the exact unproved historical claim")
    try:
        record = json.loads(target_payload_bytes)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("invalid target pre-oracle payload") from error
    if not isinstance(record, dict) or set(record) != {
        "schema_version", "claim_name", "claim_ast", "claim_ast_sha256",
        "target_native_preoracle_log_sha256",
        "historical_source_payload_sha256", "target_claim_established",
        "native_target_proof_replay_executed", "reliance_authorization",
    } or (
        record["schema_version"] != "rtk.lean_target_claim_export.v1-development"
        or record["claim_name"] != "rtk_unproven_target_claim"
        or record["claim_ast"] != source["claim_ast"]
        or record["claim_ast_sha256"] != _digest(source["claim_ast"])
        or record["historical_source_payload_sha256"] != _sha(source_payload_bytes)
        or record["target_native_preoracle_log_sha256"] != _sha(native_log.encode())
        or any(record[x] is not False for x in (
            "target_claim_established",
            "native_target_proof_replay_executed",
            "reliance_authorization",
        ))
    ):
        raise ValueError("target payload not bound to native pre-oracle claim")
    return observed


def _contains_imported_op(expr: object) -> bool:
    if not isinstance(expr, list) or not expr:
        raise ValueError("malformed restricted expression")
    if expr[0] == "const":
        return expr[1] == ["str", ["anonymous"], "op"]
    kind = expr[0]
    if kind == "app":
        children = expr[1:3]
    elif kind in ("lam", "forallE"):
        children = expr[2:4]
    elif kind == "letE":
        children = expr[2:5]
    elif kind in ("bvar", "sort", "natVal", "strVal"):
        children = ()
    else:
        # Projections/metadata and previously unknown expression constructors
        # have no justified support-completeness model in this fragment.
        raise ValueError("expression outside bounded identity screen fragment")
    return any(_contains_imported_op(child) for child in children)


def evaluate_patched_preoracle(
    *, source_payload_bytes: bytes, checked_source_bytes: bytes,
    source_structural_log: str, source_recheck_log: str,
    target_payload_bytes: bytes, target_structural_log: str,
    source_support_olean: bytes, target_support_olean: bytes,
    checker_binary_bytes: bytes,
) -> dict[str, Any]:
    if _sha(checker_binary_bytes) != _EXPECTED_LEAN_SHA:
        raise ValueError("unsupported or altered patched Lean executable")
    if not source_support_olean or not target_support_olean:
        raise ValueError("missing imported module bytes")
    source = _source(source_payload_bytes)
    if source["source_checked_file_sha256"] != _sha(checked_source_bytes):
        raise ValueError("source certificate bound to different source input")
    native_source = _structural_ast(source_structural_log)
    if (
        native_source["theorem_name"] != "historical_claim"
        or native_source["theorem_kind"] != "theorem"
        or native_source["theorem_type_ast"] != source["claim_ast"]
        or native_source["theorem_value_ast"] != source["proof_ast"]
        or source["source_native_log_sha256"] != _sha(source_structural_log.encode())
    ):
        raise ValueError("historical source proof not bound to native source AST")
    _native_source_rechecked(native_log=source_recheck_log, source=source)
    native_target = _target_record(
        native_log=target_structural_log,
        target_payload_bytes=target_payload_bytes,
        source_payload_bytes=source_payload_bytes, source=source,
    )
    if native_source["op_name"] != "op" or native_target["op_name"] != "op":
        raise ValueError("imported definition subject changed")
    if native_source["op_type_ast"] != native_target["op_type_ast"]:
        raise ValueError("imported declaration type changed outside fixed fragment")
    if not _contains_imported_op(source["claim_ast"]):
        raise ValueError("historical claim outside imported op experiment")
    same_bytes = source_support_olean == target_support_olean
    same_definition_ast = (
        native_source["op_value_ast"] == native_target["op_value_ast"]
    )
    if same_bytes and not same_definition_ast:
        raise ValueError("same imported bytes report contradictory definition AST")
    if same_bytes:
        decision = "CONDITIONAL_IDENTITY_CANDIDATE"
        reason = "exact_imported_support_bytes_and_native_definition_ast"
    else:
        decision = "REVALIDATION_REQUIRED"
        reason = (
            "imported_op_definition_structural_drift"
            if not same_definition_ast else
            "whole_import_module_drift_with_unchanged_observed_op"
        )
    return {
        "schema_version": _SCHEMA,
        "patched_lean_version": "4.35.0",
        "checker_binary_sha256": _sha(checker_binary_bytes),
        "source_payload_sha256": _sha(source_payload_bytes),
        "target_claim_payload_sha256": _sha(target_payload_bytes),
        "source_checked_input_sha256": _sha(checked_source_bytes),
        "source_support_olean_sha256": _sha(source_support_olean),
        "target_support_olean_sha256": _sha(target_support_olean),
        "source_proof_expr_ast_sha256": _digest(source["proof_ast"]),
        "statement_ast_sha256": _digest(source["claim_ast"]),
        "native_source_recheck_log_sha256": _sha(source_recheck_log.encode()),
        "native_target_preoracle_log_sha256": _sha(target_structural_log.encode()),
        "decision": decision,
        "reason_code": reason,
        "source_proof_rechecked_in_separate_process": True,
        "statement_ast_identical": True,
        "imported_module_bytes_identical": same_bytes,
        "observed_imported_definition_ast_identical": same_definition_ast,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "external_provenance_authenticated": False,
        "complete_kernel_semantic_support_proved": False,
        "source_target_environment_equivalence_proved": False,
        "patched_checker_relying_policy_qualified": False,
        "production_reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "source-payload", "source-checked-input", "source-structural-log",
        "source-recheck-log", "target-payload", "target-structural-log",
        "source-olean", "target-olean", "checker-binary", "output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    a = parser.parse_args()
    result = evaluate_patched_preoracle(
        source_payload_bytes=a.source_payload.read_bytes(),
        checked_source_bytes=a.source_checked_input.read_bytes(),
        source_structural_log=a.source_structural_log.read_text(),
        source_recheck_log=a.source_recheck_log.read_text(),
        target_payload_bytes=a.target_payload.read_bytes(),
        target_structural_log=a.target_structural_log.read_text(),
        source_support_olean=a.source_olean.read_bytes(),
        target_support_olean=a.target_olean.read_bytes(),
        checker_binary_bytes=a.checker_binary.read_bytes(),
    )
    with a.output.open("x") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print("PATCHED_PREORACLE_" + result["decision"] + "_NO_RELIANCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
