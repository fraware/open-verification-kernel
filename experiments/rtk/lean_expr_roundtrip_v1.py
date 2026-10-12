"""Correlate source and target native encode/decode witnesses.

The Lean-side witness proves equality *within the native process* for a
restricted Expr fragment and separately kernel-checks reconstructed source
proof term. These records are caller-supplied bytes and do not authenticate
that process. They do not establish historical target applicability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_structural_expr_v1 import (
    _structural_ast,
    _digest,
    _expression,
)

_MARKER = "RTK_NATIVE_ROUNDTRIP_JSON="


def _result(raw: str) -> dict[str, Any]:
    markers = [
        line.partition(_MARKER)[2].strip()
        for line in raw.splitlines() if _MARKER in line
    ]
    if len(markers) != 1 or len(markers[0]) > 1_000_000:
        raise ValueError("expected one bounded native Lean roundtrip marker")
    try:
        record = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise ValueError("unparseable native Lean roundtrip record") from exc
    expected = {
        "schema_version", "root_name", "root_kind", "root_type_ast",
        "root_proof_ast", "op_type_ast", "op_value_ast",
        "source_proof_kernel_checked", "target_old_proof_replayed",
        "target_claim_established", "decode_encode_ast_equal",
        "decode_native_expr_equal", "malformed_metavar_rejected",
        "forged_imported_definition_rejected",
        "semantic_support_complete", "cross_environment_transport_established",
    }
    if not isinstance(record, dict) or set(record) != expected or (
        record["schema_version"] != "rtk.lean_native_expr_roundtrip.v1-development"
    ):
        raise ValueError("unexpected native Lean roundtrip evidence shape")
    if any(record[field] is not True for field in (
        "decode_encode_ast_equal", "decode_native_expr_equal",
        "malformed_metavar_rejected", "forged_imported_definition_rejected",
    )):
        raise ValueError("native roundtrip or anti-tamper check did not pass")
    if any(record[field] is not False for field in (
        "target_old_proof_replayed", "target_claim_established",
        "semantic_support_complete", "cross_environment_transport_established",
    )):
        raise ValueError("unsupported native transport or target-proof claim")
    if (record["root_name"], record["root_kind"]) not in (
        ("historical_claim", "theorem"),
        ("rtk_unproven_target_claim", "axiom"),
    ):
        raise ValueError("roundtrip wrong theorem subject or kind")
    if record["root_kind"] == "theorem":
        if record["source_proof_kernel_checked"] is not True:
            raise ValueError("decoded historical source proof not kernel checked")
        if record["root_proof_ast"] is None:
            raise ValueError("missing decoded historical proof")
    else:
        if record["source_proof_kernel_checked"] is not False or (
            record["root_proof_ast"] is not None
        ):
            raise ValueError("unproved target was assigned a proof")
    budget = [100_000]
    for field in ("root_type_ast", "op_type_ast", "op_value_ast"):
        _expression(record[field], 0, budget)
    if record["root_proof_ast"] is not None:
        _expression(record["root_proof_ast"], 0, budget)
    return record


def attest_local_roundtrip(
    *,
    source_roundtrip_log: str,
    target_roundtrip_log: str,
    source_structural_log: str,
    target_structural_log: str,
) -> dict[str, Any]:
    source = _result(source_roundtrip_log)
    target = _result(target_roundtrip_log)
    if source["root_kind"] != "theorem" or target["root_kind"] != "axiom":
        raise ValueError("source proof and target goal separation violated")
    from_struct = _structural_ast(source_structural_log)
    to_struct = _structural_ast(target_structural_log)
    for x, y in ((source, from_struct), (target, to_struct)):
        for left, right in (
            ("root_type_ast", "theorem_type_ast"),
            ("root_proof_ast", "theorem_value_ast"),
            ("op_type_ast", "op_type_ast"),
            ("op_value_ast", "op_value_ast"),
        ):
            if x[left] != y[right]:
                raise ValueError("roundtrip native AST contradicts prior native serialization")
    if source["root_type_ast"] != target["root_type_ast"] or (
        source["op_type_ast"] != target["op_type_ast"]
    ):
        raise ValueError("source target native declarations unexpectedly differ")
    if source["op_value_ast"] == target["op_value_ast"]:
        raise ValueError("expected development semantic-drift control absent")
    return {
        "schema_version": "rtk.lean_native_local_roundtrip_pair.v1-development",
        "checker_version": "4.14.0",
        "source_native_roundtrip_log_sha256": hashlib.sha256(
            source_roundtrip_log.encode()
        ).hexdigest(),
        "target_native_roundtrip_log_sha256": hashlib.sha256(
            target_roundtrip_log.encode()
        ).hexdigest(),
        "source_claim_type_ast_sha256": _digest(source["root_type_ast"]),
        "target_claim_type_ast_sha256": _digest(target["root_type_ast"]),
        "source_proof_expr_ast_sha256": _digest(source["root_proof_ast"]),
        "source_imported_op_ast_sha256": _digest(source["op_value_ast"]),
        "target_imported_op_ast_sha256": _digest(target["op_value_ast"]),
        "native_decode_encode_roundtrip_verified": True,
        "native_source_decoded_proof_kernel_checked": True,
        "target_unproved_goal_roundtrip_verified": True,
        "target_old_proof_replayed": False,
        "target_claim_established": False,
        "native_decoder_formally_verified": False,
        "independent_log_provenance_verified": False,
        "complete_semantic_support_established": False,
        "historical_transport_applicability": "UNDETERMINED",
        "reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in (
        "source-roundtrip-log", "target-roundtrip-log",
        "source-structural-log", "target-structural-log", "output",
    ):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    record = attest_local_roundtrip(
        source_roundtrip_log=args.source_roundtrip_log.read_text(),
        target_roundtrip_log=args.target_roundtrip_log.read_text(),
        source_structural_log=args.source_structural_log.read_text(),
        target_structural_log=args.target_structural_log.read_text(),
    )
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print("LEAN_NATIVE_SOURCE_KERNEL_ROUNDTRIP_RECORDED_NO_TARGET_REPLAY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
