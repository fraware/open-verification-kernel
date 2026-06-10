#!/usr/bin/env python
"""Validate verification intent templates against the JSON schema."""

from __future__ import annotations

import argparse
from pathlib import Path

from jsonschema import Draft202012Validator

from ovk.core.json_io import read_json_file


SCHEMA_PATH = Path("schemas/verification.intent.schema.json")
TEMPLATES_DIR = Path("templates")


def validate_templates(template_dir: Path = TEMPLATES_DIR) -> list[str]:
    """Return validation failure messages for template JSON files."""
    schema = read_json_file(SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    failures: list[str] = []
    for path in sorted(template_dir.rglob("*.intent.json")):
        try:
            instance = read_json_file(path)
        except (OSError, ValueError) as error:
            failures.append(f"{path}: could not read template ({error})")
            continue
        errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.path))
        for error in errors:
            failures.append(f"{path}: {list(error.path)} {error.message}")
        provenance = instance.get("provenance", {})
        if provenance.get("generated") and provenance.get("source") != "ovk-template-library":
            failures.append(f"{path}: generated templates must declare ovk-template-library provenance")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate OVK intent templates")
    parser.add_argument("--template-dir", type=Path, default=TEMPLATES_DIR)
    args = parser.parse_args()
    failures = validate_templates(args.template_dir)
    for failure in failures:
        print(failure)
    if failures:
        return 1
    count = len(list(args.template_dir.rglob("*.intent.json")))
    print(f"OVK template validation passed ({count} templates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
