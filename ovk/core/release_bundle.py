"""Unified release bundle writer and verifier."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ovk.core.attestation_binding import verify_bundle_statement_binding, verify_envelope_manifest_binding
from ovk.core.attestation_envelope import build_attestation_envelope
from ovk.core.attestation_signing import verify_envelope_signature
from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.output_validation import validate_generated_file, validate_generated_json, validate_output_directory
from ovk.core.provenance import build_provenance_statement
from ovk.core.models import EvidenceBundle
from ovk.core.release_layout import ReleaseArtifact, missing_required_artifacts
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs
from ovk.core.artifact_manifest import artifact_entry, build_artifact_manifest, sha256_file


DEFAULT_BUNDLE_ARTIFACTS = [
    ReleaseArtifact("ovk-evidence.json", "evidence"),
    ReleaseArtifact("ovk-pr-comment.md", "markdown"),
    ReleaseArtifact("ovk-attestation.json", "attestation"),
    ReleaseArtifact("ovk-artifact-manifest.json", "artifact_manifest"),
    ReleaseArtifact("ovk-evidence-quality.json", "evidence_quality"),
    ReleaseArtifact("ovk-provenance.json", "provenance"),
    ReleaseArtifact("ovk-attestation-envelope.json", "attestation_envelope"),
]


@dataclass(frozen=True)
class ReleaseBundlePaths:
    """Output paths for a unified release bundle."""

    root: Path
    evidence: Path | None = None
    markdown: Path | None = None
    attestation: Path | None = None
    manifest: Path | None = None
    quality_report: Path | None = None
    envelope: Path | None = None
    provenance: Path | None = None
    materials: list[Path] | None = None

    def resolved(self) -> StandardOutputPaths:
        """Return standard output paths with defaults under root."""
        return StandardOutputPaths(
            evidence=self.evidence or self.root / "ovk-evidence.json",
            markdown=self.markdown or self.root / "ovk-pr-comment.md",
            attestation=self.attestation or self.root / "ovk-attestation.json",
            manifest=self.manifest or self.root / "ovk-artifact-manifest.json",
            quality_report=self.quality_report or self.root / "ovk-evidence-quality.json",
        )


def release_bundle_layout() -> dict[str, Any]:
    """Return the full release bundle layout including quality and envelope."""
    return {
        "schema_version": "ovk.release_layout.v1",
        "artifacts": [artifact.to_dict() for artifact in DEFAULT_BUNDLE_ARTIFACTS],
    }


def write_release_bundle(
    bundle: EvidenceBundle,
    paths: ReleaseBundlePaths,
) -> dict[str, Path]:
    """Write a complete release bundle and return written artifact paths."""
    layout = release_bundle_layout()
    layout_report = validate_generated_json(layout, "release_layout")
    if not layout_report.valid:
        issues = "; ".join(issue.message for issue in layout_report.issues)
        raise ValueError(f"release layout failed schema validation: {issues}")

    paths.root.mkdir(parents=True, exist_ok=True)
    standard = paths.resolved()
    write_standard_run_outputs(
        bundle,
        StandardOutputPaths(
            evidence=standard.evidence,
            markdown=standard.markdown,
            attestation=standard.attestation,
            manifest=None,
            quality_report=standard.quality_report,
        ),
    )

    provenance_path = paths.provenance or paths.root / "ovk-provenance.json"
    provenance = build_provenance_statement(bundle, materials=paths.materials or [])
    write_json_file(provenance_path, provenance)

    manifest_path = standard.manifest or paths.root / "ovk-artifact-manifest.json"
    manifest_root = manifest_path.parent.resolve()
    entries = [
        artifact_entry(standard.evidence, kind="evidence", root=manifest_root),
        artifact_entry(standard.markdown, kind="markdown", root=manifest_root),
        artifact_entry(standard.attestation, kind="attestation", root=manifest_root),
        artifact_entry(provenance_path, kind="provenance", root=manifest_root),
    ]
    if standard.quality_report is not None and standard.quality_report.exists():
        entries.append(artifact_entry(standard.quality_report, kind="evidence_quality", root=manifest_root))
    write_json_file(manifest_path, build_artifact_manifest(entries))

    envelope_path = paths.envelope or paths.root / "ovk-attestation-envelope.json"
    attestation = read_json_file(standard.attestation)
    envelope = build_attestation_envelope(
        statement=attestation,
        manifest_path=manifest_path,
    )
    write_json_file(envelope_path, envelope)

    validation_failures = validate_output_directory(paths.root)
    if validation_failures:
        raise ValueError("; ".join(validation_failures))

    return {
        "evidence": standard.evidence,
        "markdown": standard.markdown,
        "attestation": standard.attestation,
        "manifest": standard.manifest or paths.root / "ovk-artifact-manifest.json",
        "quality_report": standard.quality_report or paths.root / "ovk-evidence-quality.json",
        "envelope": envelope_path,
        "provenance": provenance_path,
    }


def verify_release_bundle(root: Path, layout: dict[str, Any] | None = None) -> list[str]:
    """Verify a release bundle directory exists and manifest hashes match."""
    failures: list[str] = []
    active_layout = layout or release_bundle_layout()
    failures.extend(f"missing artifact: {path}" for path in missing_required_artifacts(root, active_layout))

    manifest_path = root / "ovk-artifact-manifest.json"
    if not manifest_path.exists():
        return failures

    manifest = read_json_file(manifest_path)
    for entry in manifest.get("artifacts", []):
        if not isinstance(entry, dict):
            continue
        rel_path = str(entry.get("path", ""))
        expected_sha = str(entry.get("sha256", ""))
        candidate = Path(rel_path)
        artifact_path = candidate if candidate.is_absolute() else root / rel_path
        if not artifact_path.exists():
            failures.append(f"manifest references missing file: {rel_path}")
            continue
        actual_sha = sha256_file(artifact_path)
        if expected_sha and actual_sha != expected_sha:
            failures.append(f"hash mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}")

    envelope_path = root / "ovk-attestation-envelope.json"
    evidence_path = root / "ovk-evidence.json"
    if envelope_path.exists():
        envelope = read_json_file(envelope_path)
        if envelope.get("signature") and not verify_envelope_signature(envelope):
            failures.append("attestation envelope signature verification failed")
        if evidence_path.exists():
            bundle = EvidenceBundle.model_validate(read_json_file(evidence_path))
            statement = envelope.get("statement", {})
            for issue in verify_bundle_statement_binding(bundle, statement):
                failures.append(f"attestation binding: {issue.message}")
            for issue in verify_envelope_manifest_binding(envelope, manifest_sha256=sha256_file(manifest_path)):
                failures.append(f"envelope binding: {issue.message}")

    return failures


LaneRunner = Callable[..., EvidenceBundle]


def run_lane_and_write_bundle(
    runner: LaneRunner,
    paths: ReleaseBundlePaths,
    **runner_kwargs: Any,
) -> EvidenceBundle:
    """Run a lane runner that returns EvidenceBundle and write release bundle."""
    bundle = runner(**runner_kwargs)
    write_release_bundle(bundle, paths)
    return bundle
