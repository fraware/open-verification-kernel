"""Verify a bounded Lean --trust=0 source-certificate/target-context receipt.

Development-only record. A native trust-zero header and exact source proof
recheck are necessary inputs, not independent supply-chain attestation.
No oracle, target proof, or production VALID is used or produced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_historical_target_oracle_v1 import _source
from experiments.rtk.lean_preoracle_byte_identity_v1 import _kernel_header
from experiments.rtk.lean_structural_expr_v1 import _digest, _structural_ast
from experiments.rtk.lean_imported_proofrefs_v1 import (
    _environment_modules, imported_olean_snapshot,
)
from experiments.rtk.lean_native_preoracle_envelope_v1 import _modules

_SCHEMA = "rtk.lean_trust_zero_context_receipt.v1-development"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def observe_trust_zero(
    *,
    source_payload_bytes: bytes,
    checked_source_witness: dict[str, Any],
    source_header_log: str,
    target_header_log: str,
    target_structural_log: str,
    source_reference_log: str,
    target_reference_log: str,
    source_root: Path,
    target_root: Path,
) -> dict[str, Any]:
    source = _source(source_payload_bytes)
    if not isinstance(checked_source_witness, dict) or any(
        checked_source_witness.get(k) is not True for k in (
            "separate_process_native_source_proof_type_checked",
            "native_source_proof_type_matches_serialized_claim",
            "historical_theorem_not_in_new_environment",
        )
    ) or (
        checked_source_witness.get("serialized_payload_sha256") != _sha(source_payload_bytes)
        or checked_source_witness.get("source_checked_proof_ast_sha256") !=
        _digest(source["proof_ast"])
        or checked_source_witness.get("source_claim_ast_sha256") !=
        _digest(source["claim_ast"])
        or any(checked_source_witness.get(k) is not False for k in (
            "target_historical_proof_replayed", "target_claim_established",
            "complete_semantic_support_proved", "reliance_authorization",
        ))
    ):
        raise ValueError("exact source certificate is not bound to a native recheck")

    a = _kernel_header(source_header_log, "historical_claim", "theorem")
    b = _kernel_header(target_header_log, "rtk_unproven_target_claim", "axiom")
    if any(header["trust_level"] != 0 for header in (a, b)):
        raise ValueError("source and target must independently report native trust zero")
    if not a["quotient_initialized"] or not b["quotient_initialized"]:
        raise ValueError("source and target quotient initialization must be established")

    target = _structural_ast(target_structural_log)
    if target["theorem_name"] != "rtk_unproven_target_claim" or (
        target["theorem_kind"] != "axiom" or target["theorem_value_ast"] is not None
    ):
        raise ValueError("target observation was not strictly unproved")
    if target["theorem_type_ast"] != source["claim_ast"]:
        raise ValueError("zero-trust target claim differs from source certificate")
    source_modules = _environment_modules(source_reference_log)
    target_modules = _environment_modules(target_reference_log)
    if set(source_modules) != set(target_modules) or not source_modules:
        raise ValueError("zero-trust source/target imported module inventory differs")
    if "RTKSemanticSupport" not in source_modules:
        raise ValueError("bounded imported fixture module absent")
    src_snapshot = imported_olean_snapshot(
        {name: name for name in source_modules}, source_root
    )
    dst_snapshot = imported_olean_snapshot(
        {name: name for name in target_modules}, target_root
    )
    src_snapshot, _, _ = _modules(src_snapshot)
    dst_snapshot, _, _ = _modules(dst_snapshot)
    changed = sorted(
        name for name in source_modules
        if src_snapshot[name] != dst_snapshot[name]
    )
    return {
        "schema_version": _SCHEMA,
        "source_serialized_certificate_sha256": _sha(source_payload_bytes),
        "source_checked_proof_ast_sha256": _digest(source["proof_ast"]),
        "target_unproved_claim_ast_sha256": _digest(target["theorem_type_ast"]),
        "source_native_header_log_sha256": _sha(source_header_log.encode()),
        "target_native_header_log_sha256": _sha(target_header_log.encode()),
        "source_native_reference_log_sha256": _sha(source_reference_log.encode()),
        "target_native_reference_log_sha256": _sha(target_reference_log.encode()),
        "source_imported_module_snapshot_sha256": _sha(
            json.dumps(src_snapshot, sort_keys=True).encode()
        ),
        "target_imported_module_snapshot_sha256": _sha(
            json.dumps(dst_snapshot, sort_keys=True).encode()
        ),
        "changed_imported_modules": changed,
        "source_imported_module_count": len(source_modules),
        "target_imported_module_count": len(target_modules),
        "source_proof_kernel_checked_under_trust_zero": True,
        "native_trust_zero_observed_in_both_contexts": True,
        "target_claim_unproved_under_trust_zero": True,
        "semantic_support_complete_proved": False,
        "import_integrity_independently_authenticated": False,
        "relying_policy_authenticated": False,
        "independent_runner_attestation": False,
        "target_historical_proof_replayed": False,
        "oracle_consulted": False,
        "production_reliance_authorized": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in (
        "source-payload", "source-witness",
        "source-header-log", "target-header-log", "target-structural-log",
        "source-reference-log", "target-reference-log", "source-root",
        "target-root", "output",
    ):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    receipt = observe_trust_zero(
        source_payload_bytes=a.source_payload.read_bytes(),
        checked_source_witness=json.loads(a.source_witness.read_text()),
        source_header_log=a.source_header_log.read_text(),
        target_header_log=a.target_header_log.read_text(),
        target_structural_log=a.target_structural_log.read_text(),
        source_reference_log=a.source_reference_log.read_text(),
        target_reference_log=a.target_reference_log.read_text(),
        source_root=a.source_root,
        target_root=a.target_root,
    )
    with a.output.open("x") as file:
        file.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print("NATIVE_TRUST_ZERO_CERTIFICATE_AND_UNPROVED_TARGET_CONTEXT_BOUND_NO_RELIANCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
