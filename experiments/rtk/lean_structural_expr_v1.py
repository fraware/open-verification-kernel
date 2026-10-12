"""Strict projection of native checked Lean Expr constructors into versioned AST IDs.

The checker-side serializer is experiments/rtk/lean_structural_expr_probe_v1.lean.txt.
Unlike Expr.repr this representation declares every supported constructor and
rejects unsupported metavariables and metadata. This is an *encoder for a
restricted expression fragment*, not proof of formal semantic completeness or
a transport authorization. Native source log provenance and imported-module
closure remain external review obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

_MARKER = "RTK_STRUCTURAL_EXPR_JSON="
_SCHEMA = "rtk.lean_native_structural_expr.v1-development"
_NAME = {"anonymous": 1, "str": 3, "num": 3}
_LEVEL = {"zero": 1, "succ": 2, "max": 3, "imax": 3, "param": 2}
_EXPR = {
    "bvar": 2, "sort": 2, "const": 3, "app": 3,
    "lam": 5, "forallE": 5, "letE": 6,
    "natVal": 2, "strVal": 2, "proj": 4,
}
_BINDER = {"default", "implicit", "strictImplicit", "instImplicit"}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _nat(value: object) -> bool:
    return type(value) is int and value >= 0


def _name(value: object, depth: int) -> None:
    if depth > 128 or not isinstance(value, list) or not value:
        raise ValueError("invalid or too-deep structural Lean Name")
    kind = value[0]
    if kind not in _NAME or len(value) != _NAME[kind]:
        raise ValueError("invalid structural Lean Name constructor")
    if kind == "str":
        _name(value[1], depth + 1)
        if not isinstance(value[2], str):
            raise ValueError("invalid Lean Name string")
    elif kind == "num":
        _name(value[1], depth + 1)
        if not _nat(value[2]):
            raise ValueError("invalid Lean Name numeral")


def _level(value: object, depth: int) -> None:
    if depth > 1024 or not isinstance(value, list) or not value:
        raise ValueError("invalid or too-deep Lean universe Level")
    kind = value[0]
    if kind not in _LEVEL or len(value) != _LEVEL[kind]:
        raise ValueError("unsupported universe Level node")
    if kind == "succ":
        _level(value[1], depth + 1)
    elif kind in {"max", "imax"}:
        _level(value[1], depth + 1)
        _level(value[2], depth + 1)
    elif kind == "param":
        _name(value[1], 0)


def _expression(value: object, depth: int, budget: list[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > 1024:
        raise ValueError("Lean AST resource limit exceeded")
    if not isinstance(value, list) or not value:
        raise ValueError("non-structural Lean expression node")
    kind = value[0]
    if kind not in _EXPR or len(value) != _EXPR[kind]:
        raise ValueError("unknown Lean expression constructor")
    if kind == "bvar" and not _nat(value[1]):
        raise ValueError("invalid bound variable")
    if kind == "sort":
        _level(value[1], 0)
    elif kind == "const":
        _name(value[1], 0)
        if not isinstance(value[2], list) or len(value[2]) > 1024:
            raise ValueError("invalid universe instantiation")
        for u in value[2]:
            _level(u, 0)
    elif kind == "app":
        _expression(value[1], depth + 1, budget)
        _expression(value[2], depth + 1, budget)
    elif kind in {"lam", "forallE"}:
        _name(value[1], 0)
        _expression(value[2], depth + 1, budget)
        _expression(value[3], depth + 1, budget)
        if value[4] not in _BINDER:
            raise ValueError("invalid binder annotation")
    elif kind == "letE":
        _name(value[1], 0)
        for child in value[2:5]:
            _expression(child, depth + 1, budget)
        if type(value[5]) is not bool:
            raise ValueError("invalid let binder nondependency flag")
    elif kind == "natVal" and not _nat(value[1]):
        raise ValueError("invalid natural literal")
    elif kind == "strVal" and not isinstance(value[1], str):
        raise ValueError("invalid string literal")
    elif kind == "proj":
        _name(value[1], 0)
        if not _nat(value[2]):
            raise ValueError("invalid projection index")
        _expression(value[3], depth + 1, budget)


def _structural_ast(raw: str) -> dict[str, Any]:
    markers = [
        line.split(_MARKER, 1)[1].strip()
        for line in raw.splitlines() if _MARKER in line
    ]
    if len(markers) != 1 or len(markers[0]) > 1_000_000:
        raise ValueError("one bounded native AST result required")
    try:
        record = json.loads(markers[0])
    except json.JSONDecodeError as error:
        raise ValueError("invalid native AST JSON") from error
    expected = {
        "schema_version", "theorem_name", "theorem_kind",
        "theorem_type_ast", "theorem_value_ast",
        "op_name", "op_type_ast", "op_value_ast",
        "unsupported_constructs_silently_omitted",
        "imported_support_closure_proved",
    }
    if not isinstance(record, dict) or set(record) != expected:
        raise ValueError("unknown native AST record shape")
    if record["schema_version"] != _SCHEMA:
        raise ValueError("wrong native AST protocol version")
    if record["theorem_name"] not in {
        "historical_claim", "rtk_unproven_target_claim"
    } or record["op_name"] != "op":
        raise ValueError("wrong native proof or imported definition subject")
    if record["theorem_kind"] not in {"theorem", "axiom"}:
        raise ValueError("unknown native theorem kind")
    if record["unsupported_constructs_silently_omitted"] is not False:
        raise ValueError("unsupported native AST construct was omitted")
    if record["imported_support_closure_proved"] is not False:
        raise ValueError("unsupported closure proof claim")
    if record["theorem_kind"] == "axiom":
        if record["theorem_name"] != "rtk_unproven_target_claim" or (
            record["theorem_value_ast"] is not None
        ):
            raise ValueError("target axiom contains a theorem proof")
    else:
        if record["theorem_name"] != "historical_claim":
            raise ValueError("unexpected checked source theorem")
    budget = [100_000]
    for field in ("theorem_type_ast", "op_type_ast", "op_value_ast"):
        _expression(record[field], 0, budget)
    if record["theorem_kind"] == "theorem":
        _expression(record["theorem_value_ast"], 0, budget)
    return record


def analyze_structural_pair(
    source_log: str,
    target_log: str,
) -> dict[str, Any]:
    """Compare source-checked proof versus unproved target statement only."""
    old = _structural_ast(source_log)
    new = _structural_ast(target_log)
    if old["theorem_kind"] != "theorem" or new["theorem_kind"] != "axiom":
        raise ValueError("source proof / unproved target separation violated")
    if old["theorem_type_ast"] != new["theorem_type_ast"]:
        raise ValueError("formal source and target statement ASTs differ")
    if old["op_type_ast"] != new["op_type_ast"]:
        raise ValueError("imported declaration type AST differs")
    changed = old["op_value_ast"] != new["op_value_ast"]
    return {
        "schema_version": "rtk.lean_structural_imported_drift.v1-development",
        "checker_version": "4.14.0",
        "source_structural_log_sha256": hashlib.sha256(
            source_log.encode("utf-8")
        ).hexdigest(),
        "target_structural_log_sha256": hashlib.sha256(
            target_log.encode("utf-8")
        ).hexdigest(),
        "source_theorem_type_ast_sha256": _digest(old["theorem_type_ast"]),
        "target_theorem_type_ast_sha256": _digest(new["theorem_type_ast"]),
        "source_historical_proof_ast_sha256": _digest(old["theorem_value_ast"]),
        "source_op_type_ast_sha256": _digest(old["op_type_ast"]),
        "target_op_type_ast_sha256": _digest(new["op_type_ast"]),
        "source_op_value_ast_sha256": _digest(old["op_value_ast"]),
        "target_op_value_ast_sha256": _digest(new["op_value_ast"]),
        "imported_definition_structural_drift": changed,
        "statement_structural_ast_identical": True,
        "target_claim_established": False,
        "target_historical_proof_replayed": False,
        "structural_encoding_is_native_kernel_expr_ast": True,
        "cross_environment_semantic_completeness_proved": False,
        "serialized_expr_deserialization_kernel_checked": False,
        "native_ast_log_provenance_authenticated": False,
        "transport_applicability": "UNDETERMINED",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-native-log", type=Path, required=True)
    parser.add_argument("--target-native-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze_structural_pair(
        args.source_native_log.read_text(),
        args.target_native_log.read_text(),
    )
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("NATIVE_STRUCTURAL_EXPRESSION_DRIFT_RECORDED_NO_TARGET_PROOF")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
