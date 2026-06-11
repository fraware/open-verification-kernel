#!/usr/bin/env python
"""Validate adapter capability manifests against the JSON schema."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import validate_against_schema
from ovk.paths import ovk_data_root, schema_path


def discover_capability_files(root: Path | None = None) -> list[Path]:
    """Return all adapter capability.json files under the data root."""
    base = root or ovk_data_root()
    return sorted(base.glob("adapters/*/capability.json"))


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
    args = parser.parse_args()
    files = args.capability_files or discover_capability_files()
    failures = validate_capabilities(files)
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print(f"OVK capability validation passed ({len(files)} manifests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
