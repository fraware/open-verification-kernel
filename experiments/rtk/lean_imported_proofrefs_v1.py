"""Bounded Lean proof-reference inspection without target proof replay.

Consumes source-side checked native support metadata; emits read-only Lean
target-environment lookup commands for the imported names in that source.
Hashes exact .olean files backing observed module names under an exact Lean
toolchain root. This is only a development inspection, not a sound support
closure or a portable Lean kernel-certificate oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from experiments.rtk.lean_native_support_projection import (
    project_native_probe,
)

_SUPPORT_MARKER = "RTK_NATIVE_SUPPORT_JSON="
_REFERENCES_MARKER = "RTK_NATIVE_REFERENCE_JSON="
_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.']*$")
_EXPECTED_LEAN_BINARY = (
    "eacf754d25ae86ea076882a34b9444f2485659d9df4266b821443b28ca95a215"
)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_json(log: str, marker: str) -> dict[str, Any]:
    entries = [
        line.partition(marker)[2].strip()
        for line in log.splitlines()
        if marker in line
    ]
    if len(entries) != 1:
        raise ValueError("expected exactly one native marker: " + marker)
    try:
        result = json.loads(entries[0])
    except json.JSONDecodeError as error:
        raise ValueError("malformed native JSON result") from error
    if not isinstance(result, dict):
        raise ValueError("nonobject native result")
    return result


def source_imported_symbols(source_log: str) -> dict[str, str]:
    """Source-only discovery: never inspect target native oracle results."""
    native = _extract_json(source_log, _SUPPORT_MARKER)
    projection = project_native_probe(native)
    imported = projection["imported_modules"]
    if not imported:
        raise ValueError("no imported proof support to inspect")
    return imported


def generate_reference_probe(source_log: str) -> str:
    """Native target *environment lookup* for the old source's imported names.

    This code references constant declarations by name; it NEVER elaborates
    the source proof term, asserts an old proposition or rechecks evidence.
    """
    names = sorted(source_imported_symbols(source_log))
    if len(names) > 256:
        raise ValueError("too many imported reference lookup names")
    if any(not _MODULE.fullmatch(x) for x in names):
        raise ValueError("unsafe imported reference name")
    literals = ", ".join("`" + name for name in names)
    return """\n/- Research-only source-derived imported constant lookup. No proof replay. -/
open Lean Elab Command
run_cmd do
  let env ← getEnv
  let requested : Array Name := #[""" + literals + """]
  let mut items : Array Json := #[]
  for symbol in requested do
    let some ci := env.find? symbol
      | throwError m!"RTK_TARGET_PROOF_REFERENCE_ABSENT: {symbol}"
    let some idx := env.getModuleIdxFor? symbol
      | throwError m!"RTK_TARGET_PROOF_REFERENCE_NOT_IMPORTED: {symbol}"
    let some moduleName := env.allImportedModuleNames[idx.toNat]?
      | throwError m!"RTK_TARGET_PROOF_REFERENCE_MODULE_MISSING: {symbol}"
    let kind : String := match ci with
      | .thmInfo _ => "theorem"
      | .defnInfo _ => "definition"
      | .opaqueInfo _ => "opaque"
      | .axiomInfo _ => "axiom"
      | .ctorInfo _ => "constructor"
      | .recInfo _ => "recursor"
      | .inductInfo _ => "inductive"
      | .quotInfo _ => "quotient"
    items := items.push <| Json.mkObj [
      ("symbol", Json.str symbol.toString),
      ("module", Json.str moduleName.toString),
      ("kind", Json.str kind),
      ("type_repr", Json.str (toString (repr ci.type)))
    ]
  let fullModuleNames : Array Json := env.allImportedModuleNames.map fun name => Json.str name.toString
  logInfo m!"RTK_NATIVE_REFERENCE_JSON={Json.compress (Json.mkObj [
    ("schema_version", Json.str "rtk.lean_imported_ref_lookup.v1-development"),
    ("environment_modules", Json.arr fullModuleNames),
    ("items", Json.arr items)
  ])}"
"""


def _reference_record(log: str, expected: dict[str, str]) -> dict[str, dict[str, str]]:
    raw = _extract_json(log, _REFERENCES_MARKER)
    if set(raw) != {"schema_version", "items", "environment_modules"} or (
        raw["schema_version"] != "rtk.lean_imported_ref_lookup.v1-development"
    ):
        raise ValueError("unsupported reference observation")
    if not isinstance(raw["items"], list) or len(raw["items"]) != len(expected):
        raise ValueError("missing or extra native references")
    records: dict[str, dict[str, str]] = {}
    for entry in raw["items"]:
        if not isinstance(entry, dict) or set(entry) != {
            "symbol", "module", "kind", "type_repr"
        } or any(not isinstance(v, str) for v in entry.values()):
            raise ValueError("malformed native reference")
        symbol, module = entry["symbol"], entry["module"]
        if symbol in records or expected.get(symbol) != module or not entry["type_repr"]:
            raise ValueError("wrong module, duplicate, or untyped native reference")
        records[symbol] = entry
    if set(records) != set(expected):
        raise ValueError("reference identity mismatch")
    return records


def _environment_modules(log: str) -> list[str]:
    """Capture all imported module names from the native checker environment.

    This is a loaded-module inventory, NOT a semantic soundness proof.
    """
    raw = _extract_json(log, _REFERENCES_MARKER)
    values = raw.get("environment_modules")
    if not isinstance(values, list) or not 1 <= len(values) <= 2048:
        raise ValueError("missing or excessively large native imported module set")
    if any(not isinstance(x, str) or not _MODULE.fullmatch(x) or "'" in x
           for x in values) or len(set(values)) != len(values):
        raise ValueError("invalid or duplicated native imported modules")
    return sorted(values)


def _module_paths(module: str, root: Path) -> Path:
    """Resolve an exact installed module, refusing symlink or root escape."""
    if not _MODULE.fullmatch(module) or "'" in module:
        raise ValueError("unsupported imported module path")
    base = root / "lib" / "lean"
    path = base.joinpath(*module.split(".")).with_suffix(".olean")
    if not path.is_file() or path.is_symlink():
        raise ValueError("missing or redirected imported .olean: " + module)
    if not path.resolve().is_relative_to(base.resolve()):
        raise ValueError("imported .olean path escapes toolchain root")
    return path


def imported_olean_snapshot(imported: dict[str, str], lean_root: Path) -> dict[str, dict[str, Any]]:
    modules = sorted(set(imported.values()))
    if not modules or len(modules) > 2048:
        raise ValueError("unsupported imported module inventory")
    result = {}
    total_bytes = 0
    for name in modules:
        path = _module_paths(name, lean_root)
        stat = path.stat()
        if not 0 < stat.st_size < 128 * 1024 * 1024:
            raise ValueError("unsupported imported .olean file size")
        total_bytes += stat.st_size
        if total_bytes > 512 * 1024 * 1024:
            raise ValueError("imported module inventory exceeds 512 MiB limit")
        file_bytes = path.read_bytes()
        if len(file_bytes) != stat.st_size:
            raise ValueError("changed imported module size during read")
        result[name] = {
            "relative_path": str(path.relative_to(lean_root)),
            "file_sha256": _hash(file_bytes),
            "file_size_bytes": len(file_bytes),
        }
    return result


def compare_imported_proof_references(
    *,
    source_native_log: str,
    source_ref_log: str,
    target_ref_log: str,
    target_goal_native_log: str,
    lean_root: Path,
    checker_binary: Path,
) -> dict[str, Any]:
    """Refuses malformed data; accepted results still leave transport unknown."""
    if _hash(checker_binary.read_bytes()) != _EXPECTED_LEAN_BINARY:
        raise ValueError("checker executable differs from pinned Lean 4.14.0")
    imported = source_imported_symbols(source_native_log)
    source = _reference_record(source_ref_log, imported)
    target = _reference_record(target_ref_log, imported)
    # Validate target goal native support is a synthetic unproved axiom;
    # do not confuse its successful context parsing with target truth.
    goal = _extract_json(target_goal_native_log, _SUPPORT_MARKER)
    project_native_probe(goal)
    if goal["root"] != "rtk_unproven_target_claim":
        raise ValueError("unexpected target goal identity")
    roots = {node["symbol"]: node for node in goal["items"]}
    root = roots[goal["root"]]
    if root["kind"] != "axiom" or root["value_repr"] != "":
        raise ValueError("target was not an unproved claim placeholder")
    modules = imported_olean_snapshot(imported, lean_root)
    source_loaded = _environment_modules(source_ref_log)
    target_loaded = _environment_modules(target_ref_log)
    if source_loaded != target_loaded:
        raise ValueError("source and target imported module inventories diverge")
    # This captures the actual complete *loaded module-name inventory*.
    # It still does not prove that those modules are semantically complete.
    loaded_modules = imported_olean_snapshot(
        {name: name for name in source_loaded}, lean_root
    )
    if not set(modules).issubset(loaded_modules):
        raise ValueError("source proof imports outside native loaded modules")
    changed = sorted(name for name in source if source[name] != target[name])
    return {
        "schema_version": "rtk.lean_imported_proofref_transport.v1-development",
        "checker_sha256": _EXPECTED_LEAN_BINARY,
        "imported_olean_module_files": modules,
        "module_file_count": len(modules),
        "loaded_environment_olean_files": loaded_modules,
        "loaded_environment_module_count": len(loaded_modules),
        "source_target_loaded_module_inventory_identical": True,
        "source_imported_proof_references": source,
        "target_imported_proof_references": target,
        "reference_count": len(source),
        "reference_differences": changed,
        "reference_identity_matches_in_this_environment": not changed,
        "module_bytes_reproducibly_hashed": True,
        "different_source_target_module_installations_compared": False,
        "target_proof_supplied": False,
        "target_old_proof_replayed": False,
        "target_goal_established": False,
        "transitive_import_semantics_proved": False,
        "imported_module_semantic_closure_proved": False,
        "lean_expression_serialization_canonical": False,
        "transport_applicability_established": False,
        "source_native_log_sha256": _hash(source_native_log.encode()),
        "source_reference_log_sha256": _hash(source_ref_log.encode()),
        "target_reference_log_sha256": _hash(target_ref_log.encode()),
        "target_goal_native_log_sha256": _hash(target_goal_native_log.encode()),
    }


def _new_file(path: Path, contents: str) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(contents)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--make-footer-from-source-log", type=Path)
    parser.add_argument("--footer-output", type=Path)
    parser.add_argument("--source-native-log", type=Path)
    parser.add_argument("--source-reference-log", type=Path)
    parser.add_argument("--target-reference-log", type=Path)
    parser.add_argument("--target-goal-native-log", type=Path)
    parser.add_argument("--lean-root", type=Path)
    parser.add_argument("--checker-binary", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.make_footer_from_source_log is not None:
        if args.footer_output is None:
            parser.error("footer output required")
        _new_file(args.footer_output, generate_reference_probe(
            args.make_footer_from_source_log.read_text()
        ))
        print("SOURCE_REFERENCES_FOR_TARGET_INSPECTION_COMPILED")
        return 0
    required = [
        "source_native_log", "source_reference_log",
        "target_reference_log", "target_goal_native_log",
        "lean_root", "checker_binary", "output",
    ]
    if any(getattr(args, x) is None for x in required):
        parser.error("all native reference and environment records required")
    evidence = compare_imported_proof_references(
        source_native_log=args.source_native_log.read_text(),
        source_ref_log=args.source_reference_log.read_text(),
        target_ref_log=args.target_reference_log.read_text(),
        target_goal_native_log=args.target_goal_native_log.read_text(),
        lean_root=args.lean_root,
        checker_binary=args.checker_binary,
    )
    _new_file(args.output, json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("BOUND_IMPORTED_OLEAN_REFERENCE_DEV_CONTROL_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
