"""Development-only declaration-identity hypothesis for a fixed Lean 4.35 proof.

This module is deliberately more selective than the whole-.olean identity
baseline. It is NOT a Lean semantic-support extractor or soundness theorem.
It may report a conditional research candidate, NEVER a production VALID.
The target historical certificate must not be replayed until predictions
and native observations have been sealed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_historical_target_oracle_v1 import _source
from experiments.rtk.lean_patched_preoracle_identity_v1 import (
    evaluate_patched_preoracle,
)
from experiments.rtk.lean_structural_expr_v1 import _structural_ast

_SCHEMA = "rtk.lean_patched_declaration_hypothesis.v1-development"
_ALLOWED_REFERENCES = frozenset({"Nat", "Eq", "Eq.refl", "op"})


def _name(value: object) -> str:
    """Decode ordinary structural names; reject inaccessible/mangled forms."""
    if value == ["anonymous"]:
        return ""
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError("unsupported declaration name")
    if value[0] != "str" or not isinstance(value[2], str) or not value[2]:
        raise ValueError("unsupported declaration name")
    prefix = _name(value[1])
    return (prefix + "." if prefix else "") + value[2]


def _references(expr: object, *, remaining: list[int]) -> set[str]:
    """Inspect all constant positions in the intentionally tiny expression subset.

    A complete Lean kernel dependency traversal is NOT claimed. Unsupported
    nodes are an explicit unresolved result and never a candidate.
    """
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ValueError("expression exceeds support-inspection budget")
    if not isinstance(expr, list) or not expr:
        raise ValueError("invalid structural expression")
    tag = expr[0]
    if tag == "const" and len(expr) == 3:
        if not isinstance(expr[2], list) or expr[2]:
            raise ValueError("nonempty universe instantiation excluded")
        return {_name(expr[1])}
    if tag == "app" and len(expr) == 3:
        return _references(expr[1], remaining=remaining) | _references(
            expr[2], remaining=remaining
        )
    if tag in {"lam", "forallE"} and len(expr) == 5:
        if expr[4] not in {"default", "implicit", "strictImplicit", "instImplicit"}:
            raise ValueError("unsupported binder metadata")
        return _references(expr[2], remaining=remaining) | _references(
            expr[3], remaining=remaining
        )
    if tag == "bvar" and len(expr) == 2 and type(expr[1]) is int and expr[1] >= 0:
        return set()
    if tag == "sort" and len(expr) == 2 and expr[1] == ["zero"]:
        return set()
    raise ValueError("expression outside declared development fragment")


def _admitted_references(source: dict[str, Any], op_type: object,
                         op_value: object) -> tuple[str, ...]:
    found: set[str] = set()
    for expr in (source["claim_ast"], source["proof_ast"], op_type, op_value):
        found.update(_references(expr, remaining=[20_000]))
    if "op" not in found or not found <= _ALLOWED_REFERENCES:
        raise ValueError("unaccounted-for proof or imported-definition references")
    return tuple(sorted(found))


def evaluate_declaration_hypothesis(
    *, source_payload_bytes: bytes, checked_source_bytes: bytes,
    source_structural_log: str, source_recheck_log: str,
    target_payload_bytes: bytes, target_structural_log: str,
    source_support_olean: bytes, target_support_olean: bytes,
    checker_binary_bytes: bytes,
) -> dict[str, Any]:
    """Classify a *hypothesis* after validating all baseline evidence bindings.

    Every field passed here is a pre-replay source or target observation. Target
    oracle results, freshly generated target proofs, and policy permissions are
    intentionally absent from this interface.
    """
    base = evaluate_patched_preoracle(
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
    source = _source(source_payload_bytes)
    a = _structural_ast(source_structural_log)
    b = _structural_ast(target_structural_log)

    # Under #210's established binding rules, the same name/type and identical
    # statement have already been checked. Here we inspect the *observed*
    # declaration body rather than promote module identity to semantic identity.
    if a["op_value_ast"] != b["op_value_ast"]:
        decision = "REVALIDATION_REQUIRED"
        reason = "observed_imported_definition_changed"
        refs: tuple[str, ...] = ()
    else:
        try:
            refs = _admitted_references(
                source, a["op_type_ast"], a["op_value_ast"]
            )
        except ValueError:
            decision = "UNRESOLVED"
            reason = "unsupported_or_unaccounted_declaration_support"
            refs = ()
        else:
            decision = "CONDITIONAL_DECLARATION_CANDIDATE"
            reason = "same_native_observed_op_type_and_body_in_bounded_fixture"

    return {
        "schema_version": _SCHEMA,
        "decision": decision,
        "reason_code": reason,
        "baseline_identity_decision": base["decision"],
        "baseline_identity_reason": base["reason_code"],
        "source_payload_sha256": base["source_payload_sha256"],
        "target_claim_payload_sha256": base["target_claim_payload_sha256"],
        "checker_binary_sha256": base["checker_binary_sha256"],
        "source_support_olean_sha256": base["source_support_olean_sha256"],
        "target_support_olean_sha256": base["target_support_olean_sha256"],
        "historical_proof_ast_sha256": base["source_proof_expr_ast_sha256"],
        "statement_ast_sha256": base["statement_ast_sha256"],
        "source_native_recheck_sha256": base["native_source_recheck_log_sha256"],
        "target_native_observation_sha256": base["native_target_preoracle_log_sha256"],
        "observed_imported_declaration_ast_equal":
            base["observed_imported_definition_ast_identical"],
        "imported_module_bytes_identical": base["imported_module_bytes_identical"],
        "inspected_direct_reference_names": list(refs),
        "reference_allowlist_is_complete_kernel_support": False,
        "actual_kernel_support_preservation_proved": False,
        "native_observation_to_loaded_environment_binding_proved": False,
        "source_target_environment_equivalence_proved": False,
        "external_provenance_authenticated": False,
        "relying_policy_authorized": False,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
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
    result = evaluate_declaration_hypothesis(
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
    with a.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print("PATCHED_DECLARATION_" + result["decision"] + "_NO_RELIANCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
