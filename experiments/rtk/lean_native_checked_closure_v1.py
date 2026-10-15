"""Validate bounded native checked-declaration closure before historical replay.

A declaration graph closed under the observable constant-reference relation is
NOT proof that it contains every dependency of Lean.Kernel.check. Only a
conditional research decision is emitted; no production reliance is permitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from experiments.rtk.lean_historical_target_oracle_v1 import _source
from experiments.rtk.lean_patched_declaration_hypothesis_v1 import _references
from experiments.rtk.lean_patched_preoracle_identity_v1 import evaluate_patched_preoracle
from experiments.rtk.lean_structural_expr_v1 import _structural_ast

_MARKER = "RTK_NATIVE_CHECKED_CLOSURE_JSON="
_SCHEMA = "rtk.lean_checked_definition_closure.v1-development"
_BASE = frozenset({"Eq", "Eq.refl", "Nat", "Nat.succ"})
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_'.]*$")
_MAX_NODES = 32
_MAX_REFS = 96


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _names(expr: object) -> set[str]:
    """Independently inspect accepted expression nodes; reject unknown forms."""
    return _references(expr, remaining=[20_000])


def _name_list(value: object, *, max_count: int) -> list[str]:
    if (not isinstance(value, list) or len(value) > max_count
        or any(not isinstance(s, str) or not _NAME.fullmatch(s) for s in value)
        or len(value) != len(set(value))):
        raise ValueError("duplicated or malformed declaration names")
    # Lean's Name.lt orders structured names, which need not agree with
    # Python string sorting of Name.toString. Normalize after checking
    # uniqueness and validate exactly the resulting identity set.
    return sorted(value)


def _manifest(log: str, *, expected_root: str, expected_kind: str,
              observed: dict[str, Any], historical_proof: object | None) -> dict[str, Any]:
    entries = [line.partition(_MARKER)[2].strip()
               for line in log.splitlines() if _MARKER in line]
    if len(entries) != 1 or len(entries[0]) > 800_000:
        raise ValueError("expected exactly one bounded native closure receipt")
    try:
        record = json.loads(entries[0])
    except json.JSONDecodeError as exc:
        raise ValueError("invalid native closure JSON") from exc
    keys = {
        "schema_version", "root_name", "root_kind", "root_type_ast",
        "root_proof_ast", "root_type_references", "root_proof_references",
        "trusted_core_frontier", "nodes",
        "native_declaration_relation_exhaustive_for_kernel_proved",
        "core_frontier_semantics_authenticated",
        "historical_target_certificate_replayed", "relying_authorization",
    }
    if (not isinstance(record, dict) or set(record) != keys
        or record["schema_version"] != _SCHEMA
        or record["root_name"] != expected_root
        or record["root_kind"] != expected_kind
        or any(record[key] is not False for key in (
            "native_declaration_relation_exhaustive_for_kernel_proved",
            "core_frontier_semantics_authenticated",
            "historical_target_certificate_replayed", "relying_authorization",
        ))):
        raise ValueError("native closure receipt missing, mismatched or claims authority")
    if record["root_type_ast"] != observed["theorem_type_ast"]:
        raise ValueError("checked root type differs from structural source/target witness")
    if record["root_proof_ast"] != historical_proof:
        raise ValueError("checked root proof differs from source certificate or target is proved")
    if record["trusted_core_frontier"] != sorted(_BASE):
        raise ValueError("unexpected trusted core frontier")
    if _name_list(record["root_type_references"], max_count=_MAX_REFS) != sorted(
        _names(observed["theorem_type_ast"])
    ):
        raise ValueError("root type reference discrepancy")
    expected_proof_refs = [] if historical_proof is None else sorted(_names(historical_proof))
    if _name_list(record["root_proof_references"], max_count=_MAX_REFS) != expected_proof_refs:
        raise ValueError("historical proof root reference discrepancy")
    nodes = record["nodes"]
    if not isinstance(nodes, list) or len(nodes) > _MAX_NODES:
        raise ValueError("bounded closure graph required")
    by_name: dict[str, dict[str, Any]] = {}
    node_keys = {
        "name", "kind", "type_ast", "value_ast", "level_params",
        "reducibility_hint", "safety", "direct_references",
        "native_full_semantic_support_proved",
    }
    for node in nodes:
        if not isinstance(node, dict) or set(node) != node_keys:
            raise ValueError("malformed native closure node")
        name = node["name"]
        if (not isinstance(name, str) or not _NAME.fullmatch(name)
            or name in _BASE or name in by_name
            or node["kind"] != "definition" or node["safety"] != "safe"
            or node["native_full_semantic_support_proved"] is not False
            or node["level_params"] != []):
            raise ValueError("unsupported, duplicated or unqualified closure node")
        hint = node["reducibility_hint"]
        if (not isinstance(hint, list) or len(hint) not in (1, 2)
            or (hint not in (["opaque"], ["abbrev"])
                and not (len(hint) == 2 and hint[0] == "regular"
                         and type(hint[1]) is int and 0 <= hint[1] < 2**32))):
            raise ValueError("unsupported native reducibility metadata")
        refs = _name_list(node["direct_references"], max_count=_MAX_REFS)
        if refs != sorted(_names(node["type_ast"]) | _names(node["value_ast"])):
            raise ValueError("native graph edges disagree with independently visited AST")
        by_name[name] = node

    roots = set(record["root_type_references"]) | set(record["root_proof_references"])
    if any(not _NAME.fullmatch(n) for n in roots):
        raise ValueError("malformed root name")
    reached: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in _BASE or name in reached:
            continue
        if name not in by_name:
            raise ValueError("missing non-core declaration in reachable closure")
        reached.add(name)
        if len(reached) > _MAX_NODES:
            raise ValueError("closure budget exceeded")
        pending.extend(by_name[name]["direct_references"])
    if reached != set(by_name):
        raise ValueError("extraneous or disconnected native closure nodes")
    # No cycles admitted in the restricted definition fragment.
    def has_cycle(name: str, active: frozenset[str], done: set[str]) -> bool:
        if name in active:
            return True
        if name in done or name in _BASE:
            return False
        next_active = active | {name}
        if any(has_cycle(child, next_active, done)
               for child in by_name[name]["direct_references"] if child not in _BASE):
            return True
        done.add(name)
        return False
    complete: set[str] = set()
    if any(has_cycle(n, frozenset(), complete) for n in by_name):
        raise ValueError("cyclic definition support excluded from fragment")
    return {
        "root_kind": expected_kind,
        "root_type_references": record["root_type_references"],
        "root_proof_references": record["root_proof_references"],
        "nodes": by_name,
    }


def evaluate_checked_closure(
    *, source_payload_bytes: bytes, checked_source_bytes: bytes,
    source_structural_log: str, source_recheck_log: str,
    target_payload_bytes: bytes, target_structural_log: str,
    source_support_olean: bytes, target_support_olean: bytes,
    checker_binary_bytes: bytes,
) -> dict[str, Any]:
    """Classify declaration-level differences without accessing target replay."""
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
    source = _source(source_payload_bytes)
    a = _manifest(
        source_structural_log, expected_root="historical_claim",
        expected_kind="historical_theorem",
        observed=_structural_ast(source_structural_log),
        historical_proof=source["proof_ast"],
    )
    b = _manifest(
        target_structural_log, expected_root="rtk_unproven_target_claim",
        expected_kind="unproved_target_placeholder",
        observed=_structural_ast(target_structural_log),
        historical_proof=None,
    )
    # A new target proof is forbidden. Source proof references not included
    # in the target claim must be entirely within the pinned core frontier.
    proof_only = set(a["root_proof_references"]) - set(b["root_type_references"])
    if not proof_only <= _BASE:
        raise ValueError("historical proof references absent from target support")
    if a["root_type_references"] != b["root_type_references"]:
        raise ValueError("source/target claim reference identities disagree")
    if "op" not in a["nodes"]:
        raise ValueError("fixture missing imported op")
    src_nodes, dst_nodes = a["nodes"], b["nodes"]
    differing = sorted(
        name for name in src_nodes.keys() | dst_nodes.keys()
        if src_nodes.get(name) != dst_nodes.get(name)
    )
    return {
        "schema_version": "rtk.lean_checked_closure_preoracle.v1-development",
        "decision": (
            "REVALIDATION_REQUIRED" if differing
            else "CONDITIONAL_CLOSED_REFERENCE_CANDIDATE"
        ),
        "changed_declaration_names": differing,
        "observed_closed_noncore_names": sorted(src_nodes),
        "trusted_core_frontier": sorted(_BASE),
        "baseline_identity_decision": baseline["decision"],
        "source_payload_sha256": _sha(source_payload_bytes),
        "target_payload_sha256": _sha(target_payload_bytes),
        "source_native_log_sha256": _sha(source_structural_log.encode()),
        "target_native_log_sha256": _sha(target_structural_log.encode()),
        "checker_binary_sha256": baseline["checker_binary_sha256"],
        "source_module_sha256": baseline["source_support_olean_sha256"],
        "target_module_sha256": baseline["target_support_olean_sha256"],
        "closure_complete_relative_to_extracted_reference_relation": True,
        "kernel_semantic_dependency_completeness_proved": False,
        "trusted_core_environment_authenticated": False,
        "actual_kernel_preservation_theorem_proved": False,
        "target_historical_proof_replayed": False,
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
    result = evaluate_checked_closure(
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
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("RTK_NATIVE_CHECKED_CLOSURE_" + result["decision"] + "_NO_RELIANCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
