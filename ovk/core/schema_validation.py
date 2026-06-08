"""Schema validation helpers for OVK artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


@dataclass(frozen=True)
class ValidationIssue:
    """One schema validation issue."""

    path: list[str | int]
    message: str


@dataclass(frozen=True)
class ValidationReport:
    """Validation result for an artifact."""

    valid: bool
    issues: list[ValidationIssue]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_against_schema(instance: dict[str, Any], schema: dict[str, Any]) -> ValidationReport:
    """Validate a JSON object against a JSON schema."""
    validator = Draft202012Validator(schema)
    issues = [
        ValidationIssue(path=list(error.path), message=error.message)
        for error in sorted(validator.iter_errors(instance), key=lambda item: item.path)
    ]
    return ValidationReport(valid=not issues, issues=issues)


def validate_file(instance_path: Path, schema_path: Path) -> ValidationReport:
    """Validate one JSON file against one JSON schema file."""
    return validate_against_schema(load_json(instance_path), load_json(schema_path))
