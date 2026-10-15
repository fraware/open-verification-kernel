"""Research-only pre-replay comparison of native Lean op/base declarations.

The admitted fixture has historical support through op -> base.
This is not a general Lean support extractor or a kernel transport theorem.
No oracle result, target historical proof, or relying authority is consumed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_historical_target_oracle_v1 import _source
from experiments.rtk.lean_patched_declaration_hypothesis_v1 import _references
from experiments.rtk.lean_patched_preoracle_identity_v1 import evaluate_patched_preoracle
from experiments.rtk.lean_structural_expr_v1 import _structural_ast

_MARKER = "RTK_TRANSITIVE_DECLARATION_JSON="
_SCHEMA = "rtk.lean_native_transitive_declaration.v1-development"
_ALLOWED = frozenset({"Nat", "Eq", "Eq.refl", "op", "base"})


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _native_record(log: str) -> dict[str, Any]:
    matches = [line.partition(_MARKER)[2].strip()
               for line in log.splitlines() if _MARKER in line]
    if len(matches) != 1 or len(matches[0]) > 400_000:
        raise ValueError("exactly one bounded transitive native record required")
    try:
        row = json.loads(matches[0])
    except json.JSONDecodeError as exc:
        raise ValueError("malformed transitive native JSON") from exc
    if not isinstance(row, dict) or set(row) != {
        "schema_version", "base_name", "base_kind", "base_type_ast",
        "base_value_ast", "op_name", "op_kind", "op_value_ast",
        "support_completeness_proved", "historical_certificate_replayed",
        "relying_authority",
    }:
        raise ValueError("unknown or missing transitive native fields")
    if (
        row["schema_version"] != _SCHEMA
        or row["base_name"] != "base" or row["base_kind"] != "definition"
        or row["op_name"] != "op" or row["op_kind"] != "definition"
        or any(row[key] is not False for key in (
            "support_completeness_proved", "historical_certificate_replayed",
            "relying_authority",
        ))
    ):
        raise ValueError("transitive native record claims unsupported authority")
    return row


def _names(*exprs: object) -> set[str]:
    names: set[str] = set()
    for expr in exprs:
        names |= _references(expr, remaining=[20_000])
    return names


def evaluate_native_transitive_boundary(
    *, source_payload_bytes: bytes, checked_source_bytes: bytes,
    source_structural_log: str, source_recheck_log: str,
    target_payload_bytes: bytes, target_structural_log: str,
    source_support_olean: bytes, target_support_olean: bytes,
    checker_binary_bytes: bytes,
) -> dict[str, Any]:
    """Validate prior evidence bindings, then inspect two native declarations."""
    baseline = evaluate_patched_preoracle(
        source_payload_bytes=source_payload_bytes,
        checked_source_bytes=checked_source_bytes,
        source_structural_log=source_structural_log,
        source_recheck_log=source_recheck_log,
        target_payload_bytes=target_payload_bytes,
        target_structural_log=target_structural_log,
        source_support_olean=source_support_olean,
        target_support_olean=target_support_olean,
        checker_binary_bytes=checker_binary_bytes,
    )
    certificate = _source(source_payload_bytes)
    source, target = (_native_record(log) for log in (
        source_structural_log, target_structural_log,
    ))
    source_op = _structural_ast(source_structural_log)
    target_op = _structural_ast(target_structural_log)
    if (source["op_value_ast"] != source_op["op_value_ast"]
        or target["op_value_ast"] != target_op["op_value_ast"]):
        raise ValueError("two native observations disagree on op expression")

    support: tuple[str, ...] = ()
    if source["op_value_ast"] != target["op_value_ast"]:
        decision, reason = "REVALIDATION_REQUIRED", "op_declaration_drift"
    elif source["base_type_ast"] != target["base_type_ast"]:
        decision, reason = "REVALIDATION_REQUIRED", "base_type_drift"
    elif source["base_value_ast"] != target["base_value_ast"]:
        decision, reason = "REVALIDATION_REQUIRED", "transitive_base_drift"
    else:
        try:
            references = _names(
                certificate["claim_ast"], certificate["proof_ast"],
                source_op["op_type_ast"], source["op_value_ast"],
                source["base_type_ast"], source["base_value_ast"],
                target_op["op_type_ast"], target["op_value_ast"],
                target["base_type_ast"], target["base_value_ast"],
            )
            op_body_refs = _names(source["op_value_ast"])
        except (ValueError, RecursionError):
            decision, reason = "UNRESOLVED", "unsupported_structural_expression"
        else:
            if (references <= _ALLOWED and {"op", "base"} <= references
                and "base" in op_body_refs):
                decision = "CONDITIONAL_TRANSITIVE_CANDIDATE"
                reason = "same_observed_op_and_transitive_base_declarations"
                support = tuple(sorted(references))
            else:
                decision, reason = "UNRESOLVED", "unknown_kernel_support_reference"
    return {
        "schema_version": "rtk.lean_native_transitive_preoracle.v1-development",
        "decision": decision,
        "reason_code": reason,
        "baseline_identity_decision": baseline["decision"],
        "source_payload_sha256": _sha(source_payload_bytes),
        "target_payload_sha256": _sha(target_payload_bytes),
        "source_native_log_sha256": _sha(source_structural_log.encode()),
        "target_native_log_sha256": _sha(target_structural_log.encode()),
        "source_recheck_log_sha256": _sha(source_recheck_log.encode()),
        "source_olean_sha256": baseline["source_support_olean_sha256"],
        "target_olean_sha256": baseline["target_support_olean_sha256"],
        "checker_binary_sha256": baseline["checker_binary_sha256"],
        "observed_reference_names": list(support),
        "observed_op_ast_identical": source["op_value_ast"] == target["op_value_ast"],
        "observed_base_ast_identical": source["base_value_ast"] == target["base_value_ast"],
        "kernel_semantic_support_completeness_proved": False,
        "native_environment_binding_independently_attested": False,
        "actual_kernel_transport_preservation_proved": False,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "production_reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in (
        "source-payload", "source-checked-input", "source-structural-log",
        "source-recheck-log", "target-payload", "target-structural-log",
        "source-olean", "target-olean", "checker-binary", "output",
    ):
        parser.add_argument("--" + field, required=True, type=Path)
    a = parser.parse_args()
    output = evaluate_native_transitive_boundary(
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
    with a.output.open("x", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("RTK_TRANSITIVE_PREORACLE_" + output["decision"] + "_NO_RELIANCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
