"""Cross-check native Lean Expr.getUsedConstantsAsSet against encoded ASTs.

This is an independent syntactic constant-occurrence check, not a theorem
that these sets capture all kernel-relevant semantic dependencies.
"""
from __future__ import annotations

import json
from collections.abc import Callable

from experiments.rtk.lean_strict_decl_closure_v1 import _key, _name
from experiments.rtk.lean_structural_expr_v1 import _structural_ast

_MARKER = "RTK_NATIVE_EXPR_REFERENCES_JSON="
_SCHEMA = "rtk.lean_native_expr_reference_set.v1-development"
_FIELDS = (
    "root_type_const_asts", "root_proof_const_asts",
    "op_type_const_asts", "op_value_const_asts",
)


def _read_expr_refs(log: str, root: str, kind: str) -> dict:
    markers = [
        line.partition(_MARKER)[2].strip()
        for line in log.splitlines() if _MARKER in line
    ]
    if len(markers) != 1 or len(markers[0]) > 1_000_000:
        raise ValueError("one bounded native expression reference witness required")
    try:
        record = json.loads(markers[0])
    except json.JSONDecodeError as error:
        raise ValueError("malformed native expression reference witness") from error
    if not isinstance(record, dict) or set(record) != {
        "schema_version", "root_name", "root_kind", *_FIELDS,
        "expression_support_complete_for_kernel_proved",
        "target_historical_proof_replayed", "reliance_authorization",
    } or (
        record["schema_version"] != _SCHEMA
        or record["root_name"] != root or record["root_kind"] != kind
        or any(record[k] is not False for k in (
            "expression_support_complete_for_kernel_proved",
            "target_historical_proof_replayed", "reliance_authorization",
        ))
    ):
        raise ValueError("native expression witness identity or authority mismatch")
    parsed = {}
    for field in _FIELDS:
        names = record[field]
        if field == "root_proof_const_asts" and kind == "unproved_goal_placeholder":
            if names is not None:
                raise ValueError("unproved target supplied proof reference evidence")
            parsed[field] = None
            continue
        if not isinstance(names, list) or len(names) > 8192:
            raise ValueError("unbounded or missing native expression references")
        for name in names:
            _name(name)
        keys = [_key(name) for name in names]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate native expression constant identity")
        parsed[field] = set(keys)
    return parsed


def validate_expr_reference_pair(
    *,
    source_native_log: str,
    target_native_log: str,
    source_structural_log: str,
    target_structural_log: str,
    source_claim_ast: object,
    source_proof_ast: object,
    target_claim_ast: object,
    extract_constants: Callable[[object], set[str]],
) -> None:
    """Require exact syntactic constant-set agreement in both native contexts."""
    source = _structural_ast(source_structural_log)
    target = _structural_ast(target_structural_log)
    if (
        source["theorem_kind"] != "theorem"
        or source["theorem_type_ast"] != source_claim_ast
        or source["theorem_value_ast"] != source_proof_ast
        or target["theorem_kind"] != "axiom"
        or target["theorem_type_ast"] != target_claim_ast
    ):
        raise ValueError("native structural proof/claim differs from source evidence")
    cases = (
        (_read_expr_refs(source_native_log, "historical_claim", "theorem"), (
            ("root_type_const_asts", source_claim_ast),
            ("root_proof_const_asts", source_proof_ast),
            ("op_type_const_asts", source["op_type_ast"]),
            ("op_value_const_asts", source["op_value_ast"]),
        )),
        (_read_expr_refs(
            target_native_log, "rtk_unproven_target_claim",
            "unproved_goal_placeholder",
        ), (
            ("root_type_const_asts", target_claim_ast),
            ("op_type_const_asts", target["op_type_ast"]),
            ("op_value_const_asts", target["op_value_ast"]),
        )),
    )
    for native, expressions in cases:
        for field, expr in expressions:
            if native[field] != extract_constants(expr):
                raise ValueError(
                    "native Expr reference set disagrees with encoded AST"
                )
