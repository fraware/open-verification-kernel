"""Compare two *separately installed* Lean 4.14.0 environments.

The experiment reads source-checked historical proof references and the
target's UNPROVED claim context. It never replays the historical proof
against the target. It fingerprints each installation's native checker
and every module reported as imported by the respective Lean process.

Equality of installed bytes is a reproducibility observation, NOT a
soundness theorem for evidence transport or independent oracle evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_imported_proofrefs_v1 import (
    _environment_modules,
    _extract_json,
    _reference_record,
    _SUPPORT_MARKER,
    _EXPECTED_LEAN_BINARY,
    imported_olean_snapshot,
    source_imported_symbols,
)
from experiments.rtk.lean_native_support_projection import project_native_probe


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _installed_root(root: Path, executable: Path) -> Path:
    if root.is_symlink() or executable.is_symlink():
        raise ValueError("symlinked checker installation not allowed")
    if not root.is_dir() or not executable.is_file():
        raise ValueError("Lean installation missing")
    resolved = root.resolve(strict=True)
    exe = executable.resolve(strict=True)
    if not exe.is_relative_to(resolved):
        raise ValueError("checker executable outside named installation")
    if _sha256(executable.read_bytes()) != _EXPECTED_LEAN_BINARY:
        raise ValueError("unregistered native Lean 4.14.0 executable")
    return resolved


def _goal_only(log: str) -> dict[str, Any]:
    raw = _extract_json(log, _SUPPORT_MARKER)
    projection = project_native_probe(raw)
    if raw["root"] != "rtk_unproven_target_claim":
        raise ValueError("unexpected historical target claim reference")
    roots = [x for x in raw["items"] if x["symbol"] == raw["root"]]
    if len(roots) != 1 or roots[0]["kind"] != "axiom" or roots[0]["value_repr"]:
        raise ValueError("target proof supplied or non-placeholder claim")
    return {
        "target_goal_native_projection_sha256": projection["source_probe_sha256"],
        "target_goal_is_unproved_axiom_placeholder": True,
    }


def compare_separately_installed_environments(
    *,
    source_root: Path,
    target_root: Path,
    source_lean: Path,
    target_lean: Path,
    source_native_log: str,
    source_refs_log: str,
    target_refs_log: str,
    target_unproved_goal_log: str,
) -> dict[str, Any]:
    """Compare actual loaded environment files without target proof replay."""

    src = _installed_root(source_root, source_lean)
    dst = _installed_root(target_root, target_lean)
    if src == dst or source_lean.samefile(target_lean):
        raise ValueError("source and target checker installations are not distinct")

    source_deps = source_imported_symbols(source_native_log)
    source_refs = _reference_record(source_refs_log, source_deps)
    target_refs = _reference_record(target_refs_log, source_deps)
    goal = _goal_only(target_unproved_goal_log)

    source_loaded = _environment_modules(source_refs_log)
    target_loaded = _environment_modules(target_refs_log)

    # A true differential experiment admits a changed module inventory.
    source_modules = imported_olean_snapshot(
        {name: name for name in source_loaded}, src
    )
    target_modules = imported_olean_snapshot(
        {name: name for name in target_loaded}, dst
    )
    source_proof_modules = set(source_deps.values())
    if not source_proof_modules.issubset(source_modules):
        raise ValueError("source proof dependencies missing from source modules")
    if not source_proof_modules.issubset(target_modules):
        raise ValueError("source proof dependencies missing from target modules")
    common = sorted(set(source_modules) & set(target_modules))
    for module in common:
        relative = Path(source_modules[module]["relative_path"])
        if (src / relative).samefile(dst / relative):
            raise ValueError("independent installations share an imported .olean inode")

    only_source = sorted(set(source_modules) - set(target_modules))
    only_target = sorted(set(target_modules) - set(source_modules))
    content_drift = sorted(
        name for name in common
        if source_modules[name]["file_sha256"] != target_modules[name]["file_sha256"]
    )
    reference_drift = sorted(
        name for name in source_refs if source_refs[name] != target_refs[name]
    )
    byte_equal = (
        not only_source and not only_target and not content_drift
    )
    return {
        "schema_version": "rtk.lean_dual_installed_environment.v1-development",
        "source_toolchain_root": str(src),
        "target_toolchain_root": str(dst),
        "separate_executable_paths_and_inodes_verified": True,
        "checker_binary_sha256": _EXPECTED_LEAN_BINARY,
        "source_loaded_module_count": len(source_modules),
        "target_loaded_module_count": len(target_modules),
        "source_loaded_bytes": sum(
            x["file_size_bytes"] for x in source_modules.values()
        ),
        "target_loaded_bytes": sum(
            x["file_size_bytes"] for x in target_modules.values()
        ),
        "source_module_inventory_sha256": _sha256(json.dumps(
            source_modules, sort_keys=True, separators=(",", ":")
        ).encode()),
        "target_module_inventory_sha256": _sha256(json.dumps(
            target_modules, sort_keys=True, separators=(",", ":")
        ).encode()),
        "source_modules": source_modules,
        "target_modules": target_modules,
        "source_only_modules": only_source,
        "target_only_modules": only_target,
        "changed_module_bytes": content_drift,
        "old_proof_reference_differences": reference_drift,
        "old_proof_reference_count": len(source_refs),
        "environment_byte_comparison": (
            "BYTE_IDENTICAL" if byte_equal else "DRIFT_DETECTED"
        ),
        "source_native_log_sha256": _sha256(source_native_log.encode()),
        "source_refs_log_sha256": _sha256(source_refs_log.encode()),
        "target_refs_log_sha256": _sha256(target_refs_log.encode()),
        "target_goal_log_sha256": _sha256(target_unproved_goal_log.encode()),
        **goal,
        "independently_administered_builds_verified": False,
        "module_dependency_semantic_closure_proved": False,
        "cross_version_compatibility_proved": False,
        "historical_proof_replayed_on_target": False,
        "fresh_target_proof_supplied": False,
        "target_claim_established": False,
        "native_transport_oracle_executed": False,
        "transport_applicability": "UNDETERMINED",
        "reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "source-root", "target-root", "source-lean", "target-lean",
        "source-native-log", "source-refs-log", "target-refs-log",
        "target-unproved-goal-log", "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    record = compare_separately_installed_environments(
        source_root=args.source_root,
        target_root=args.target_root,
        source_lean=args.source_lean,
        target_lean=args.target_lean,
        source_native_log=args.source_native_log.read_text(encoding="utf-8"),
        source_refs_log=args.source_refs_log.read_text(encoding="utf-8"),
        target_refs_log=args.target_refs_log.read_text(encoding="utf-8"),
        target_unproved_goal_log=args.target_unproved_goal_log.read_text(encoding="utf-8"),
    )
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("DUAL_LEAN_INSTALLED_ENVIRONMENT_OBSERVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
