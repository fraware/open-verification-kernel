"""Validate PCS verifier-assurance artifacts against the pin schemas."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ovk.assurance.errors import PinError
from ovk.assurance.pcs_hash import verify_nested_integrity
from ovk.assurance.pin import (
    ARTIFACT_SCHEMA_FILES,
    ensure_pcs_on_path,
    require_pcs_pin,
    schema_path,
    schemas_dir,
)


@dataclass(frozen=True)
class PcsValidationIssue:
    path: str
    message: str


@dataclass(frozen=True)
class PcsValidationReport:
    valid: bool
    issues: list[PcsValidationIssue]


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PinError(f"schema root must be an object: {path}")
    return data


@lru_cache(maxsize=1)
def pcs_schema_registry() -> Registry:
    """Build a jsonschema registry from the pinned PCS schemas directory.

    Only JSON Schema documents are registered (``*.schema.json`` and
    ``*.defs.json``). Catalog / status JSON files under schemas/ are skipped.
    """
    from referencing.jsonschema import DRAFT202012

    root = schemas_dir()
    registry = Registry()
    paths = sorted(set(root.glob("*.schema.json")) | set(root.glob("*.defs.json")))
    for path in paths:
        schema = _load_json(path)
        if "$schema" not in schema and "$id" not in schema and "$defs" not in schema:
            continue
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        schema_id = str(schema.get("$id") or path.as_uri())
        registry = registry.with_resource(schema_id, resource)
        # Also register by basename for relative $ref resolution.
        registry = registry.with_resource(path.name, resource)
    return registry


def validate_against_pin_schema(
    artifact: dict[str, Any],
    *,
    artifact_type: str | None = None,
    check_integrity: bool = True,
) -> PcsValidationReport:
    """Validate *artifact* against the pin schema for its artifact type."""
    resolved_type = artifact_type or str(artifact.get("artifact_type") or "")
    if not resolved_type:
        return PcsValidationReport(
            valid=False,
            issues=[PcsValidationIssue(path="artifact_type", message="missing artifact_type")],
        )
    if resolved_type not in ARTIFACT_SCHEMA_FILES:
        raise PinError(f"unknown PCS assurance artifact type: {resolved_type!r}")

    schema = _load_json(schema_path(resolved_type))
    validator = Draft202012Validator(schema, registry=pcs_schema_registry())
    issues = [
        PcsValidationIssue(
            path="/".join(str(part) for part in error.path) or "$",
            message=error.message,
        )
        for error in sorted(validator.iter_errors(artifact), key=lambda item: list(item.path))
    ]

    if check_integrity and not issues:
        try:
            verify_nested_integrity(artifact)
        except PinError as exc:
            issues.append(PcsValidationIssue(path="integrity", message=str(exc)))

    return PcsValidationReport(valid=not issues, issues=issues)


def require_valid_pcs_artifact(
    artifact: dict[str, Any],
    *,
    artifact_type: str | None = None,
    check_integrity: bool = True,
) -> None:
    """Raise ``PinError`` when schema or integrity validation fails."""
    report = validate_against_pin_schema(
        artifact,
        artifact_type=artifact_type,
        check_integrity=check_integrity,
    )
    if report.valid:
        return
    detail = "; ".join(f"{issue.path}: {issue.message}" for issue in report.issues)
    raise PinError(f"PCS artifact failed validation: {detail}")


def semantic_validate(artifact: dict[str, Any]) -> list[str]:
    """Optionally run pcs_core semantic validation when importable.

    Returns a list of issue strings (empty when valid or when the semantic
    validator is unavailable). Schema validation remains the hard gate.
    """
    try:
        ensure_pcs_on_path()
        require_pcs_pin()
        from pcs_core.verifier_assurance_validate import validate_va_semantics
    except Exception:
        return []

    try:
        issues = validate_va_semantics(artifact)
    except Exception as exc:  # pragma: no cover - defensive
        return [str(exc)]
    return [str(item) for item in (issues or [])]
