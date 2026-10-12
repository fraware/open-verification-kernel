"""Validate exact serialized source payload against a second-process Lean log.

Native separate-process execution is enforced by CI orchestration. This
parser validates the externally supplied bytes and reporter flags; it is not
an independent attestation of the GitHub runner or Lean executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from experiments.rtk.lean_structural_expr_v1 import _digest, _expression

_MARKER = "RTK_SECOND_PROCESS_PROOF_JSON="


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def attest_second_process(
    *,
    payload_bytes: bytes,
    manifest: object,
    native_log: str,
    driver_bytes: bytes,
) -> dict:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "payload_sha256", "driver_sha256",
        "source_structural_log_sha256", "source_checked_file_sha256",
        "source_native_proof_expr_ast_sha256",
        "target_old_proof_replayed", "target_claim_established",
        "independent_native_process_proven",
        "source_proof_type_checked_in_new_process",
        "transport_applicability",
    } or manifest["schema_version"] != (
        "rtk.lean_second_process_export_manifest.v1-development"
    ):
        raise ValueError("invalid serialized source export manifest")
    if any(manifest[x] is not False for x in (
        "target_old_proof_replayed", "target_claim_established",
        "independent_native_process_proven",
        "source_proof_type_checked_in_new_process",
    )) or manifest["transport_applicability"] != "UNDETERMINED":
        raise ValueError("invalid export authority claims")
    if manifest["payload_sha256"] != _sha(payload_bytes) or (
        manifest["driver_sha256"] != _sha(driver_bytes)
    ):
        raise ValueError("serialized payload or driver bytes differ from manifest")
    try:
        payload = json.loads(payload_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid serialized source payload JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "declaration_name", "claim_ast", "proof_ast",
        "source_native_log_sha256", "source_checked_file_sha256",
        "source_proof_expr_ast_sha256", "historical_transport_applicability",
        "target_historical_proof_replay_executed", "target_claim_established",
        "reliance_authorization",
    } or payload["schema_version"] != (
        "rtk.lean_separate_source_proof_payload.v1-development"
    ) or payload["declaration_name"] != "historical_claim":
        raise ValueError("unknown or misidentified serialized proof record")
    if any(payload[x] is not False for x in (
        "target_historical_proof_replay_executed", "target_claim_established",
        "reliance_authorization",
    )) or payload["historical_transport_applicability"] != "UNDETERMINED":
        raise ValueError("serialized source contains target evidence contamination")
    budget = [100_000]
    _expression(payload["claim_ast"], 0, budget)
    _expression(payload["proof_ast"], 0, budget)
    if (
        _digest(payload["proof_ast"]) != payload["source_proof_expr_ast_sha256"]
        or payload["source_proof_expr_ast_sha256"] !=
        manifest["source_native_proof_expr_ast_sha256"]
        or payload["source_native_log_sha256"] !=
        manifest["source_structural_log_sha256"]
        or payload["source_checked_file_sha256"] !=
        manifest["source_checked_file_sha256"]
    ):
        raise ValueError("serialized source structural proof identity mismatch")

    markers = [
        line.partition(_MARKER)[2].strip()
        for line in native_log.splitlines() if _MARKER in line
    ]
    if len(markers) != 1 or len(markers[0]) > 1_000_000:
        raise ValueError("missing or duplicated second-process native checker witness")
    try:
        witness = json.loads(markers[0])
    except ValueError as exc:
        raise ValueError("invalid second-process Lean JSON witness") from exc
    if not isinstance(witness, dict) or set(witness) != {
        "schema_version", "declaration_name", "claim_ast", "proof_ast",
        "source_proof_kernel_checked",
        "source_proof_type_defeq_serialized_claim",
        "historical_theorem_not_imported_or_declared",
        "serialized_expr_loaded_from_disk",
        "independent_process_from_serializer",
        "target_historical_proof_replayed", "target_claim_established",
        "independently_governed_provenance",
        "transitive_support_completeness_proved",
        "transport_applicability_established",
    } or witness["schema_version"] != (
        "rtk.lean_second_process_kernel_check.v1-development"
    ) or witness["declaration_name"] != "historical_claim":
        raise ValueError("unknown second-process native witness")
    if any(witness[x] is not True for x in (
        "source_proof_kernel_checked",
        "source_proof_type_defeq_serialized_claim",
        "historical_theorem_not_imported_or_declared",
        "serialized_expr_loaded_from_disk",
        "independent_process_from_serializer",
    )):
        raise ValueError("missing kernel proof/claim verification witness")
    if any(witness[x] is not False for x in (
        "target_historical_proof_replayed", "target_claim_established",
        "independently_governed_provenance",
        "transitive_support_completeness_proved",
        "transport_applicability_established",
    )):
        raise ValueError("invalid external native reliance claim")
    if witness["claim_ast"] != payload["claim_ast"] or (
        witness["proof_ast"] != payload["proof_ast"]
    ):
        raise ValueError("second-process claim/proof AST does not match exported file")
    return {
        "schema_version": "rtk.lean_separate_kernel_claim_check.v1-development",
        "serialized_payload_sha256": _sha(payload_bytes),
        "source_native_log_sha256": payload["source_native_log_sha256"],
        "source_checker_input_sha256": payload["source_checked_file_sha256"],
        "second_process_driver_sha256": _sha(driver_bytes),
        "second_process_native_log_sha256": _sha(native_log.encode()),
        "source_checked_proof_ast_sha256": _digest(payload["proof_ast"]),
        "source_claim_ast_sha256": _digest(payload["claim_ast"]),
        "separate_process_native_source_proof_type_checked": True,
        "native_source_proof_type_matches_serialized_claim": True,
        "historical_theorem_not_in_new_environment": True,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "proof_expression_issuer_authenticity_verified": False,
        "independent_native_process_attestation_verified": False,
        "complete_semantic_support_proved": False,
        "target_transport_applicability": "UNDETERMINED",
        "reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("payload", "manifest", "native-log", "lean-driver", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    record = attest_second_process(
        payload_bytes=args.payload.read_bytes(),
        manifest=json.loads(args.manifest.read_text()),
        native_log=args.native_log.read_text(),
        driver_bytes=args.lean_driver.read_bytes(),
    )
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(record, out, indent=2, sort_keys=True)
        out.write("\n")
    print("SECOND_LEAN_PROCESS_SOURCE_CLAIM_KERNEL_CHECK_PASS_NO_TARGET_REPLAY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
