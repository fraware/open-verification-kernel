#!/usr/bin/env python
"""Validate adapter capability manifests against schema and normative rules."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.capabilities import validate_capability_manifest
from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import validate_against_schema
from ovk.paths import ovk_data_root, schema_path


def discover_capability_files(root: Path | None = None) -> list[Path]:
    """Return all adapter capability.json files under the data root."""
    base = root or ovk_data_root()
    return sorted(base.glob("adapters/*/capability.json"))


def discover_template_registry_files(root: Path | None = None) -> list[Path]:
    """Return template claim-registry entry files when present."""
    base = root or ovk_data_root()
    registry_dir = base / "templates" / "registry"
    if not registry_dir.is_dir():
        return []
    return sorted(p for p in registry_dir.glob("*.json") if p.name != "bridge.json")


def validate_capabilities(capability_files: list[Path] | None = None) -> list[str]:
    """Return validation failure messages for capability manifests."""
    schema_path_file = schema_path("verification.capability.schema.json")
    if not schema_path_file.exists():
        return ["verification.capability.schema.json is missing"]
    schema = read_json_file(schema_path_file)
    failures: list[str] = []
    for path in capability_files or discover_capability_files():
        try:
            instance = read_json_file(path)
        except (OSError, ValueError) as error:
            failures.append(f"{path}: could not read capability ({error})")
            continue
        report = validate_against_schema(instance, schema)
        for issue in report.issues:
            location = "/".join(str(part) for part in issue.path) or "$"
            failures.append(f"{path}: {location}: {issue.message}")
        failures.extend(validate_capability_manifest(instance, source=str(path)))
    return failures


def validate_template_registry(registry_files: list[Path] | None = None) -> list[str]:
    """Validate template registry entries that reuse the capability schema fields."""
    files = registry_files if registry_files is not None else discover_template_registry_files()
    if not files:
        return []
    schema_path_file = schema_path("verification.capability.schema.json")
    if not schema_path_file.exists():
        return ["verification.capability.schema.json is missing"]
    schema = read_json_file(schema_path_file)
    failures: list[str] = []
    for path in files:
        try:
            instance = read_json_file(path)
        except (OSError, ValueError) as error:
            failures.append(f"{path}: could not read template registry entry ({error})")
            continue
        # Template registry may be a list of entries or a single entry object.
        entries = instance if isinstance(instance, list) else [instance]
        if isinstance(instance, dict) and "entries" in instance:
            raw_entries = instance.get("entries")
            if not isinstance(raw_entries, list):
                failures.append(f"{path}: entries must be an array")
                continue
            entries = raw_entries
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                failures.append(f"{path}: entry[{index}] must be an object")
                continue
            source = f"{path}#[{index}]"
            report = validate_against_schema(entry, schema)
            for issue in report.issues:
                location = "/".join(str(part) for part in issue.path) or "$"
                failures.append(f"{source}: {location}: {issue.message}")
            failures.extend(validate_capability_manifest(entry, source=source))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate OVK adapter capability manifests")
    parser.add_argument(
        "--capability-file",
        type=Path,
        action="append",
        dest="capability_files",
        help="Validate one capability.json file (repeatable). Defaults to adapters/*/capability.json",
    )
    parser.add_argument(
        "--include-templates",
        action="store_true",
        help="Also validate templates/registry claim entries",
    )
    args = parser.parse_args()
    files = args.capability_files or discover_capability_files()
    failures = validate_capabilities(files)
    if args.include_templates or not args.capability_files:
        failures.extend(validate_template_registry())
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print(f"OVK capability validation passed ({len(files)} manifests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
