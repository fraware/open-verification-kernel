"""Schema validation for generated OVK artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ovk.core.models import EvidenceBundle
from ovk.core.schema_validation import ValidationIssue, ValidationReport, validate_against_schema, validate_file


from ovk.paths import ovk_data_root

SCHEMA_ROOT = ovk_data_root() / "schemas"

ARTIFACT_SCHEMAS: dict[str, Path] = {
    "quality_report": SCHEMA_ROOT / "evidence.quality.schema.json",
    "preflight_report": SCHEMA_ROOT / "preflight.report.schema.json",
    "release_layout": SCHEMA_ROOT / "release.layout.schema.json",
    "provenance": SCHEMA_ROOT / "provenance.schema.json",
    "attestation_envelope": SCHEMA_ROOT / "attestation.envelope.schema.json",
    "artifact_manifest": SCHEMA_ROOT / "artifact.manifest.schema.json",
    "attestation": SCHEMA_ROOT / "attestation.statement.schema.json",
}

RELEASE_LAYOUT_VALIDATION_KINDS: dict[str, str | None] = {
    "evidence": "evidence",
    "markdown": None,
    "attestation": "attestation",
    "artifact_manifest": "artifact_manifest",
    "evidence_quality": "quality_report",
    "provenance": "provenance",
    "attestation_envelope": "attestation_envelope",
}


def schema_for_kind(kind: str) -> Path | None:
    """Return the schema path for a generated artifact kind, if known."""
    return ARTIFACT_SCHEMAS.get(kind)


def validation_kind_for_release_artifact(kind: str) -> str | None:
    """Map a release layout artifact kind to a validation kind key."""
    if kind in RELEASE_LAYOUT_VALIDATION_KINDS:
        return RELEASE_LAYOUT_VALIDATION_KINDS[kind]
    return kind if kind in ARTIFACT_SCHEMAS or kind == "evidence" else None


def missing_release_layout_schema_coverage(layout: dict[str, Any]) -> list[str]:
    """Return failures when a release layout artifact lacks schema validation."""
    failures: list[str] = []
    for artifact in layout.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        kind = str(artifact.get("kind", ""))
        validation_kind = validation_kind_for_release_artifact(kind)
        if validation_kind is None:
            continue
        if validation_kind == "evidence":
            continue
        schema_path = schema_for_kind(validation_kind)
        if schema_path is None:
            failures.append(f"release layout kind {kind!r} has no registered schema")
        elif not schema_path.exists():
            failures.append(f"release layout kind {kind!r} schema file missing: {schema_path.name}")
    return failures


def _issues_from_pydantic(error: ValidationError) -> list[ValidationIssue]:
    return [
        ValidationIssue(path=[str(part) for part in issue["loc"]], message=issue["msg"])
        for issue in error.errors()
    ]


def validate_evidence_bundle(instance: dict[str, Any]) -> ValidationReport:
    """Validate an evidence bundle using the canonical Pydantic model."""
    try:
        EvidenceBundle.model_validate(instance)
    except ValidationError as error:
        return ValidationReport(valid=False, issues=_issues_from_pydantic(error))
    return ValidationReport(valid=True, issues=[])


def validate_generated_json(instance: dict[str, Any], kind: str) -> ValidationReport:
    """Validate a generated JSON artifact against its registered schema."""
    if kind == "evidence":
        return validate_evidence_bundle(instance)
    schema_path = schema_for_kind(kind)
    if schema_path is None or not schema_path.exists():
        return ValidationReport(valid=True, issues=[])
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return validate_against_schema(instance, schema)


def validate_generated_file(path: Path, kind: str) -> ValidationReport:
    """Validate a generated JSON file on disk."""
    if kind == "evidence":
        return validate_evidence_bundle(json.loads(path.read_text(encoding="utf-8")))
    schema_path = schema_for_kind(kind)
    if schema_path is None or not schema_path.exists():
        return ValidationReport(valid=True, issues=[])
    return validate_file(path, schema_path)


def _format_file_validation_failures(path: Path, report: ValidationReport) -> list[str]:
    return [
        f"{path.name} validation at {issue.path}: {issue.message}"
        for issue in report.issues
    ]


def validate_output_directory(root: Path) -> list[str]:
    """Validate known JSON artifacts under a release bundle directory."""
    failures: list[str] = []
    checks = [
        (root / "ovk-evidence.json", "evidence"),
        (root / "ovk-evidence-quality.json", "quality_report"),
        (root / "ovk-provenance.json", "provenance"),
        (root / "ovk-attestation.json", "attestation"),
        (root / "ovk-artifact-manifest.json", "artifact_manifest"),
        (root / "ovk-attestation-envelope.json", "attestation_envelope"),
    ]
    for path, kind in checks:
        if not path.exists():
            continue
        report = validate_generated_file(path, kind)
        if not report.valid:
            failures.extend(_format_file_validation_failures(path, report))
    return failures


def format_validation_issues(report: ValidationReport) -> list[str]:
    """Format validation issues for CLI and preflight output."""
    return [f"{list(issue.path)}: {issue.message}" for issue in report.issues]
