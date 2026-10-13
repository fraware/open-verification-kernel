"""Strict *pre-oracle* byte-identity candidate for a fixed Lean 4.14 fixture.

This module deliberately has no target replay input, no oracle parser and no
production VALID output. Identity of all natively reported imported olean
bytes plus a pinned checker yields only a CONDITIONAL candidate because neither
semantic support completeness nor external provenance/policy has been proved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_dual_installed_env_v1 import _installed_root
from experiments.rtk.lean_historical_target_oracle_v1 import (
    _source, export_target_claim,
)
from experiments.rtk.lean_imported_proofrefs_v1 import (
    _EXPECTED_LEAN_BINARY, _environment_modules, imported_olean_snapshot,
)
from experiments.rtk.lean_native_preoracle_envelope_v1 import _modules
from experiments.rtk.lean_structural_expr_v1 import _canonical, _digest
from experiments.rtk.lean_strict_decl_closure_v1 import _key, _parse

_SCHEMA = "rtk.lean_preoracle_byte_identity.v1-development"
_HEADER_MARKER = "RTK_NATIVE_KERNEL_HEADER_JSON="
_HEADER_SCHEMA = "rtk.lean_native_kernel_header.v1-development"


def _kernel_header(raw: str, root: str, kind: str) -> dict[str, Any]:
    """Parse exact native, pre-replay kernel-header observation, fail closed."""
    matches = [
        line.partition(_HEADER_MARKER)[2].strip()
        for line in raw.splitlines() if _HEADER_MARKER in line
    ]
    if len(matches) != 1 or len(matches[0]) > 8192:
        raise ValueError("one native kernel-header observation required")
    try:
        entry = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise ValueError("invalid native kernel-header JSON") from error
    if not isinstance(entry, dict) or set(entry) != {
        "schema_version", "root_name", "root_kind", "trust_level",
        "quotient_initialized", "target_historical_proof_replayed",
        "native_header_complete_environment_proof", "reliance_authorization",
    }:
        raise ValueError("unsupported native kernel-header schema")
    if (
        entry["schema_version"] != _HEADER_SCHEMA
        or entry["root_name"] != root
        or entry["root_kind"] != kind
        or type(entry["trust_level"]) is not int
        or not 0 <= entry["trust_level"] < 2**32
        or type(entry["quotient_initialized"]) is not bool
        or any(entry[k] is not False for k in (
            "target_historical_proof_replayed",
            "native_header_complete_environment_proof",
            "reliance_authorization",
        ))
    ):
        raise ValueError("native header identity or authority mismatch")
    return entry


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _used_constant_ids(expr: object) -> set[str]:
    """Collect every syntactically referenced const identity in restricted Expr AST."""
    if not isinstance(expr, list) or not expr:
        raise ValueError("non-structural proof/claim AST")
    kind = expr[0]
    if kind == "const":
        return {_key(expr[1])}
    children: list[object]
    if kind == "app":
        children = expr[1:3]
    elif kind in {"lam", "forallE"}:
        children = expr[2:4]
    elif kind == "letE":
        children = expr[2:5]
    elif kind == "proj":
        # Expr.proj carries the structure Name independently of its operand.
        # The current source/target support adapter has no certified rule for
        # constructor/recursor/projection metadata. Do not silently discard
        # this dependency and infer byte-identity eligibility.
        raise ValueError("projection outside verified pre-oracle fragment")
    else:
        children = []
    found: set[str] = set()
    for child in children:
        found.update(_used_constant_ids(child))
    return found


def _native_import_only_scope(
    *, source_closure_log: str, target_closure_log: str,
    source_proof_ast: object, source_claim_ast: object, target_claim_ast: object,
    source_modules: dict, target_modules: dict,
) -> bool:
    """Prohibit unchecked local declarations reachable from proof and statement.

    Only the source theorem / unproved target placeholder is allowed to be
    LOCAL. This bounded native reference relation is NOT kernel completeness.
    """
    cases = (
        (_parse(source_closure_log, "historical_claim", "source_theorem"),
         "historical_claim", source_modules,
         (source_proof_ast, source_claim_ast)),
        (_parse(target_closure_log, "rtk_unproven_target_claim",
                "target_goal_placeholder"),
         "rtk_unproven_target_claim", target_modules, (target_claim_ast,)),
    )
    for native, permitted_root, inventory, expressions in cases:
        root = native["root"]
        op = native["op"]
        # The kernel's local declarations are not represented by imported
        # module fingerprints. A single extra LOCAL dependency invalidates
        # this sufficiency candidate even if all .olean bytes are identical.
        for graph in (root, op):
            for entry in graph["nodes"]:
                if entry["module"] == "LOCAL":
                    if graph is op or entry["name"] != permitted_root:
                        return False
                elif entry["module"] not in inventory:
                    raise ValueError("native referenced module outside loaded inventory")
        op_root = op["index"][_key(
            native["record"]["imported_definition_closure"]["root_name_ast"]
        )]
        if op_root["name"] != "op" or op_root["module"] != "RTKSemanticSupport":
            return False
        referenced: set[str] = set()
        for expr in expressions:
            referenced.update(_used_constant_ids(expr))
        if not referenced.issubset(root["index"]):
            raise ValueError("native graph omitted a referenced proof/claim constant")
        if _key(["str", ["anonymous"], "op"]) not in referenced:
            raise ValueError("unsupported proof/claim outside imported op fragment")
    return True


def evaluate_preoracle_identity(
    *,
    environment: dict[str, Any],
    source_payload_bytes: bytes,
    source_native_witness: dict[str, Any],
    target_payload_bytes: bytes,
    target_structural_log: str,
    current_target_reference_log: str,
    source_declaration_closure_log: str,
    current_target_declaration_closure_log: str,
    source_kernel_header_log: str,
    current_target_kernel_header_log: str,
    source_root: Path,
    target_root: Path,
    source_checker: Path,
    target_checker: Path,
) -> dict[str, Any]:
    """Do not accept or access target-kernel replay records at this boundary."""
    if not isinstance(environment, dict) or environment.get(
        "schema_version"
    ) != "rtk.lean_dual_installed_environment.v1-development":
        raise ValueError("unknown pre-oracle environment schema")
    if (
        environment.get("checker_binary_sha256") != _EXPECTED_LEAN_BINARY
        or environment.get("separate_executable_paths_and_inodes_verified") is not True
        or environment.get("historical_proof_replayed_on_target") is not False
        or environment.get("native_transport_oracle_executed") is not False
        or environment.get("reliance_authorization") is not False
        or environment.get("transport_applicability") != "UNDETERMINED"
    ):
        raise ValueError("pre-oracle environment is contaminated or unsupported")
    if (
        environment.get("independently_administered_builds_verified") is not False
        or environment.get("module_dependency_semantic_closure_proved") is not False
        or environment.get("target_claim_established") is not False
    ):
        raise ValueError("unsubstantiated source/target authority flags")

    src = _installed_root(source_root, source_checker)
    tgt = _installed_root(target_root, target_checker)
    if src == tgt or source_checker.samefile(target_checker):
        raise ValueError("distinct installed checker contexts required")
    if (
        src != Path(environment.get("source_toolchain_root", "")).resolve()
        or tgt != Path(environment.get("target_toolchain_root", "")).resolve()
    ):
        raise ValueError("native imported context roots do not match source record")

    source = _source(source_payload_bytes)
    if not isinstance(source_native_witness, dict) or any(
        source_native_witness.get(k) is not True for k in (
            "separate_process_native_source_proof_type_checked",
            "native_source_proof_type_matches_serialized_claim",
            "historical_theorem_not_in_new_environment",
        )
    ) or (
        source_native_witness.get("serialized_payload_sha256")
        != _hash(source_payload_bytes)
        or source_native_witness.get("source_checked_proof_ast_sha256")
        != _digest(source["proof_ast"])
        or source_native_witness.get("source_claim_ast_sha256")
        != _digest(source["claim_ast"])
        or source_native_witness.get("source_checker_input_sha256")
        != source["source_checked_file_sha256"]
    ):
        raise ValueError("source certificate not bound to native kernel receipt")
    if any(source_native_witness.get(k) is not False for k in (
        "target_historical_proof_replayed", "target_claim_established",
        "complete_semantic_support_proved", "reliance_authorization",
    )):
        raise ValueError("source kernel receipt contains target or relying authority")

    target = json.loads(target_payload_bytes)
    if target != export_target_claim(
        source_payload_bytes=source_payload_bytes,
        target_native_log=target_structural_log,
    ):
        raise ValueError("unproved native target claim is not bound to exported AST")

    source_inventory = environment.get("source_modules")
    target_initial_inventory = environment.get("target_modules")
    src_record, source_total, source_digest = _modules(source_inventory)
    dst_record, _, _ = _modules(target_initial_inventory)
    if (
        source_digest != environment.get("source_module_inventory_sha256")
        or source_total != environment.get("source_loaded_bytes")
        or len(src_record) != environment.get("source_loaded_module_count")
    ):
        raise ValueError("historical imported module inventory is internally inconsistent")
    actual_source = imported_olean_snapshot(
        {name: name for name in src_record}, src
    )
    if actual_source != src_record:
        raise ValueError("source imported module bytes changed since native receipt")
    # These runtime fields live outside the imported .olean inventory.
    # A change to quotient initialization or a nonzero trust level does not
    # satisfy the restricted conditional reuse contract.
    source_header = _kernel_header(
        source_kernel_header_log, "historical_claim", "theorem"
    )
    target_header = _kernel_header(
        current_target_kernel_header_log, "rtk_unproven_target_claim", "axiom"
    )
    if (
        source_header["trust_level"] != 0 or target_header["trust_level"] != 0
    ):
        return _result(
            source_payload_bytes, target_payload_bytes, src_record, {},
            "UNRESOLVED", ["unsupported_nonzero_kernel_trust_level"],
        )
    if not source_header["quotient_initialized"] or not target_header[
        "quotient_initialized"
    ] or source_header["quotient_initialized"] != target_header[
        "quotient_initialized"
    ]:
        return _result(
            source_payload_bytes, target_payload_bytes, src_record, {},
            "UNRESOLVED", ["unsupported_kernel_quotient_state"],
        )
    target_native_modules = _environment_modules(current_target_reference_log)
    # Native closure is pre-outcome, derived from the checked source theorem
    # and the target's UNPROVED claim. No historical target-proof replay.
    native_import_only = _native_import_only_scope(
        source_closure_log=source_declaration_closure_log,
        target_closure_log=current_target_declaration_closure_log,
        source_proof_ast=source["proof_ast"],
        source_claim_ast=source["claim_ast"],
        target_claim_ast=target["claim_ast"],
        source_modules=src_record,
        target_modules=dst_record,
    )
    if not native_import_only:
        return _result(
            source_payload_bytes, target_payload_bytes, src_record, {},
            "UNRESOLVED", ["unaccounted_local_declaration_dependency"],
        )
    if set(target_native_modules) != set(src_record) or (
        set(target_native_modules) != set(dst_record)
    ):
        return _result(
            source_payload_bytes, target_payload_bytes, src_record, {}, 
            "UNRESOLVED", ["loaded_import_inventory_changed"],
        )
    try:
        actual_target = imported_olean_snapshot(
            {name: name for name in target_native_modules}, tgt
        )
    except (ValueError, OSError):
        return _result(
            source_payload_bytes, target_payload_bytes, src_record, {},
            "UNRESOLVED", ["target_import_acquisition_incomplete"],
        )
    changed = sorted(
        name for name in src_record
        if src_record[name]["file_sha256"] != actual_target[name]["file_sha256"]
        or src_record[name]["file_size_bytes"] != actual_target[name]["file_size_bytes"]
    )
    return _result(
        source_payload_bytes, target_payload_bytes, src_record, actual_target,
        "REVALIDATION_REQUIRED" if changed else "CONDITIONAL_IDENTITY_CANDIDATE",
        ["imported_olean_bytes_changed"] if changed
        else ["exact_reported_loaded_olean_byte_identity"],
        changed,
    )


def _result(
    source: bytes, target: bytes, source_modules: dict, target_modules: dict,
    decision: str, reasons: list[str], changed: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "historical_certificate_sha256": _hash(source),
        "target_unproved_claim_payload_sha256": _hash(target),
        "source_loaded_inventory_sha256": _hash(_canonical(source_modules)),
        "current_target_loaded_inventory_sha256": (
            _hash(_canonical(target_modules)) if target_modules else None
        ),
        "source_loaded_module_count": len(source_modules),
        "current_target_loaded_module_count": len(target_modules),
        "decision": decision,
        "reason_codes": reasons,
        "changed_imported_modules": changed or [],
        "candidate_for_reuse_under_explicit_unproved_premises": (
            decision == "CONDITIONAL_IDENTITY_CANDIDATE"
        ),
        "full_kernel_environment_equivalence_proved": False,
        "module_semantic_support_complete_proved": False,
        "native_import_only_scope_checked": (
            decision in {"REVALIDATION_REQUIRED", "CONDITIONAL_IDENTITY_CANDIDATE"}
        ),
        "native_reference_relation_semantic_completeness_proved": False,
        "native_kernel_header_supported": (
            decision in {"REVALIDATION_REQUIRED", "CONDITIONAL_IDENTITY_CANDIDATE"}
        ),
        "complete_kernel_environment_state_proved": False,
        "external_policy_and_provenance_authenticated": False,
        "target_historical_proof_replayed": False,
        "oracle_consulted": False,
        "target_claim_truth_established": False,
        "production_reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in (
        "environment", "source-payload", "source-native-witness",
        "target-payload", "target-structural-log", "target-reference-log",
        "source-root", "target-root", "source-checker", "target-checker",
        "source-declaration-closure-log", "current-target-declaration-closure-log",
        "source-kernel-header-log", "current-target-kernel-header-log",
        "output",
    ):
        parser.add_argument("--" + arg, required=True, type=Path)
    args = parser.parse_args()
    result = evaluate_preoracle_identity(
        environment=json.loads(args.environment.read_text()),
        source_payload_bytes=args.source_payload.read_bytes(),
        source_native_witness=json.loads(args.source_native_witness.read_text()),
        target_payload_bytes=args.target_payload.read_bytes(),
        target_structural_log=args.target_structural_log.read_text(),
        current_target_reference_log=args.target_reference_log.read_text(),
        source_declaration_closure_log=args.source_declaration_closure_log.read_text(),
        current_target_declaration_closure_log=(
            args.current_target_declaration_closure_log.read_text()
        ),
        source_kernel_header_log=args.source_kernel_header_log.read_text(),
        current_target_kernel_header_log=args.current_target_kernel_header_log.read_text(),
        source_root=args.source_root,
        target_root=args.target_root,
        source_checker=args.source_checker,
        target_checker=args.target_checker,
    )
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("PREORACLE_BYTE_IDENTITY_" + result["decision"] +
          "_NO_PRODUCTION_AUTHORIZATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
