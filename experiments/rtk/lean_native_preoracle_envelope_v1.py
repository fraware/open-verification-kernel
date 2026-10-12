"""Fail-closed evidence-envelope join for pre-oracle Lean development traces.

Joins exact native log bytes, two installed .olean inventories, a checked
source proof, an unproved target goal, and structural Expr AST digests.
It verifies *internal identity consistency*, not authenticity of GitHub
runner output, independent governance, or the completeness of Lean support.

A changed observed module/definition produces a conservative revalidation
recommendation. Even byte-identical observations NEVER produce VALID:
historical transport stays UNDETERMINED and reliance authority stays false.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from experiments.rtk.lean_imported_proofrefs_v1 import (
    _EXPECTED_LEAN_BINARY,
    _SUPPORT_MARKER,
    _extract_json,
    _reference_record,
    _environment_modules,
    source_imported_symbols,
)
from experiments.rtk.lean_native_support_projection import project_native_probe
from experiments.rtk.lean_structural_expr_v1 import analyze_structural_pair

_SHA = re.compile("^[0-9a-f]{64}$")
_MODULE = re.compile("^[A-Za-z_][A-Za-z0-9_.']*$")
_REQUIRED = {
    "schema_version", "source_toolchain_root", "target_toolchain_root",
    "separate_executable_paths_and_inodes_verified", "checker_binary_sha256",
    "source_loaded_module_count", "target_loaded_module_count",
    "source_loaded_bytes", "target_loaded_bytes",
    "source_module_inventory_sha256", "target_module_inventory_sha256",
    "source_modules", "target_modules", "source_only_modules",
    "target_only_modules", "changed_module_bytes",
    "old_proof_reference_differences", "old_proof_reference_count",
    "environment_byte_comparison", "source_native_log_sha256",
    "source_refs_log_sha256", "target_refs_log_sha256",
    "target_goal_log_sha256", "target_goal_native_projection_sha256",
    "target_goal_is_unproved_axiom_placeholder",
    "independently_administered_builds_verified",
    "module_dependency_semantic_closure_proved",
    "cross_version_compatibility_proved",
    "historical_proof_replayed_on_target", "fresh_target_proof_supplied",
    "target_claim_established", "native_transport_oracle_executed",
    "transport_applicability", "reliance_authorization",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _log_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _modules(modules: object) -> tuple[dict[str, dict[str, Any]], int, str]:
    if not isinstance(modules, dict) or not 1 <= len(modules) <= 2048:
        raise ValueError("invalid installed module inventory")
    total = 0
    for module, record in modules.items():
        if (
            not isinstance(module, str)
            or not _MODULE.fullmatch(module)
            or "'" in module
            or not isinstance(record, dict)
            or set(record) != {"relative_path", "file_sha256", "file_size_bytes"}
        ):
            raise ValueError("invalid native module record")
        if record["relative_path"] != (
            "lib/lean/" + module.replace(".", "/") + ".olean"
        ):
            raise ValueError("native module file identity mismatch")
        if not isinstance(record["file_sha256"], str) or not _SHA.fullmatch(
            record["file_sha256"]
        ):
            raise ValueError("invalid module byte digest")
        if type(record["file_size_bytes"]) is not int or not (
            0 < record["file_size_bytes"] < 128 * 1024 * 1024
        ):
            raise ValueError("invalid module byte length")
        total += record["file_size_bytes"]
    if total > 4 * 1024**3:
        raise ValueError("loaded-module inventory exceeds bounded byte budget")
    return modules, total, _digest(modules)


def bind_preoracle_native_evidence(
    *,
    environment: object,
    structural: object,
    source_native_log: str,
    source_reference_log: str,
    target_reference_log: str,
    target_unproved_goal_log: str,
    source_structural_log: str,
    target_structural_log: str,
    historical_proof_source: bytes,
) -> dict[str, Any]:
    """No oracle input is accepted by this function or its CLI."""

    if not isinstance(environment, dict) or set(environment) != _REQUIRED:
        raise ValueError("unexpected native environment evidence schema")
    if environment["schema_version"] != (
        "rtk.lean_dual_installed_environment.v1-development"
    ) or environment["checker_binary_sha256"] != _EXPECTED_LEAN_BINARY:
        raise ValueError("unsupported checker/environment evidence")
    if environment["separate_executable_paths_and_inodes_verified"] is not True:
        raise ValueError("separate installed checker paths not observed")
    if any(environment[key] is not False for key in (
        "independently_administered_builds_verified",
        "module_dependency_semantic_closure_proved",
        "cross_version_compatibility_proved",
        "historical_proof_replayed_on_target",
        "fresh_target_proof_supplied",
        "target_claim_established",
        "native_transport_oracle_executed",
        "reliance_authorization",
    )) or environment["transport_applicability"] != "UNDETERMINED":
        raise ValueError("oracle contamination or unsupported authority claim")

    if (
        not isinstance(environment["source_toolchain_root"], str)
        or not isinstance(environment["target_toolchain_root"], str)
        or not environment["source_toolchain_root"]
        or not environment["target_toolchain_root"]
        or environment["source_toolchain_root"]
        == environment["target_toolchain_root"]
    ):
        raise ValueError("invalid distinct toolchain root identities")

    src, src_bytes, src_id = _modules(environment["source_modules"])
    dst, dst_bytes, dst_id = _modules(environment["target_modules"])
    for side, inventory, size, identity in (
        ("source", src, src_bytes, src_id),
        ("target", dst, dst_bytes, dst_id),
    ):
        if (
            environment[side + "_loaded_module_count"] != len(inventory)
            or environment[side + "_loaded_bytes"] != size
            or environment[side + "_module_inventory_sha256"] != identity
        ):
            raise ValueError("native module inventory count/digest inconsistency")

    only_source = sorted(set(src) - set(dst))
    only_target = sorted(set(dst) - set(src))
    changed = sorted(
        x for x in set(src) & set(dst)
        if src[x]["file_sha256"] != dst[x]["file_sha256"]
        or src[x]["file_size_bytes"] != dst[x]["file_size_bytes"]
    )
    drift = bool(only_source or only_target or changed)
    for name, value in (
        ("source_only_modules", only_source),
        ("target_only_modules", only_target),
        ("changed_module_bytes", changed),
    ):
        if environment[name] != value:
            raise ValueError("reported native module drift contradicts inventories")
    if environment["environment_byte_comparison"] != (
        "DRIFT_DETECTED" if drift else "BYTE_IDENTICAL"
    ):
        raise ValueError("reported environment byte-comparison contradiction")

    input_logs = {
        "source_native_log": source_native_log,
        "source_refs_log": source_reference_log,
        "target_refs_log": target_reference_log,
        "target_goal_log": target_unproved_goal_log,
    }
    if any(
        environment[name + "_sha256"] != _log_digest(value)
        for name, value in input_logs.items()
    ):
        raise ValueError("native log bytes inconsistent with recorded digest")

    imports = source_imported_symbols(source_native_log)
    old_refs = _reference_record(source_reference_log, imports)
    new_refs = _reference_record(target_reference_log, imports)
    if not set(imports.values()).issubset(src) or not set(imports.values()).issubset(dst):
        raise ValueError("historical source proof import outside installed modules")
    diff_refs = sorted(name for name in old_refs if old_refs[name] != new_refs[name])
    if environment["old_proof_reference_count"] != len(old_refs) or (
        environment["old_proof_reference_differences"] != diff_refs
    ):
        raise ValueError("inconsistent native proof-reference observation")
    src_loaded = _environment_modules(source_reference_log)
    dst_loaded = _environment_modules(target_reference_log)
    if set(src_loaded) != set(src) or set(dst_loaded) != set(dst):
        raise ValueError("installed inventory not the native imported module inventory")

    target_goal = _extract_json(target_unproved_goal_log, _SUPPORT_MARKER)
    target_projection = project_native_probe(target_goal)
    if (
        target_goal["root"] != "rtk_unproven_target_claim"
        or target_projection["source_probe_sha256"]
        != environment["target_goal_native_projection_sha256"]
        or environment["target_goal_is_unproved_axiom_placeholder"] is not True
    ):
        raise ValueError("inconsistent unproved target claim identity")
    roots = [node for node in target_goal["items"] if node["symbol"] == target_goal["root"]]
    if len(roots) != 1 or roots[0]["kind"] != "axiom" or roots[0]["value_repr"] != "":
        raise ValueError("target goal is not an unproved axiom placeholder")

    derived_structural = analyze_structural_pair(
        source_structural_log, target_structural_log
    )
    if (
        not isinstance(structural, dict)
        or structural != derived_structural
        or structural["transport_applicability"] != "UNDETERMINED"
    ):
        raise ValueError("structural AST evidence differs from native logs")
    if not historical_proof_source or len(historical_proof_source) > 65536:
        raise ValueError("historical source term identity missing or oversized")

    # This recommendation is conservative: module drift does not logically
    # entail old proof rejection. Unchanged observed context lacks a proven
    # complete semantic closure and therefore remains unresolved.
    changed_structure = structural["imported_definition_structural_drift"]
    indicator = "REVALIDATION_REQUIRED" if (
        drift or diff_refs or changed_structure
    ) else "UNRESOLVED"

    return {
        "schema_version": "rtk.lean_preoracle_native_evidence.v1-development",
        "checker_binary_sha256": _EXPECTED_LEAN_BINARY,
        "source_proof_term_bytes_sha256": hashlib.sha256(
            historical_proof_source
        ).hexdigest(),
        "source_checked_proof_expr_ast_sha256": structural[
            "source_historical_proof_ast_sha256"
        ],
        "statement_expr_ast_sha256": structural[
            "source_theorem_type_ast_sha256"
        ],
        "source_environment_module_inventory_sha256": src_id,
        "target_environment_module_inventory_sha256": dst_id,
        "source_loaded_module_count": len(src),
        "target_loaded_module_count": len(dst),
        "source_loaded_module_bytes": src_bytes,
        "target_loaded_module_bytes": dst_bytes,
        "module_only_in_source": only_source,
        "module_only_in_target": only_target,
        "changed_imported_module_bytes": changed,
        "source_only_imported_reference_count": len(old_refs),
        "changed_imported_proof_reference_types": diff_refs,
        "source_imported_definition_ast_sha256": structural[
            "source_op_value_ast_sha256"
        ],
        "target_imported_definition_ast_sha256": structural[
            "target_op_value_ast_sha256"
        ],
        "imported_definition_structurally_changed": changed_structure,
        "conservative_action": indicator,
        "historical_evidence_applicability": "UNDETERMINED",
        "source_native_log_sha256": _log_digest(source_native_log),
        "target_unproved_goal_log_sha256": _log_digest(target_unproved_goal_log),
        "source_structural_native_log_sha256": _log_digest(source_structural_log),
        "target_structural_native_log_sha256": _log_digest(target_structural_log),
        "native_evidence_internal_integrity_checked": True,
        "independent_runner_attestation_verified": False,
        "complete_semantic_support_established": False,
        "native_expr_decoder_roundtrip_verified": False,
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False,
        "source_target_policy_authenticity_verified": False,
        "prospective_holdout_case": False,
        "reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "environment", "structural", "source-native-log",
        "source-reference-log", "target-reference-log",
        "target-unproved-goal-log", "source-structural-log",
        "target-structural-log", "historical-proof-source", "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    record = bind_preoracle_native_evidence(
        environment=json.loads(args.environment.read_text(encoding="utf-8")),
        structural=json.loads(args.structural.read_text(encoding="utf-8")),
        source_native_log=args.source_native_log.read_text(encoding="utf-8"),
        source_reference_log=args.source_reference_log.read_text(encoding="utf-8"),
        target_reference_log=args.target_reference_log.read_text(encoding="utf-8"),
        target_unproved_goal_log=args.target_unproved_goal_log.read_text(encoding="utf-8"),
        source_structural_log=args.source_structural_log.read_text(encoding="utf-8"),
        target_structural_log=args.target_structural_log.read_text(encoding="utf-8"),
        historical_proof_source=args.historical_proof_source.read_bytes(),
    )
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print("STRICT_PREORACLE_NATIVE_EVIDENCE_BOUND_WITHOUT_VALID_REUSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
