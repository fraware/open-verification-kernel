"""Helpers for writing standard OVK run outputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ovk.core.attestation import bundle_to_statement
from ovk.core.attestation_envelope import build_attestation_envelope
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import write_json_file
from ovk.core.models import EvidenceBundle
from ovk.core.render import render_bundle_markdown
from ovk.core.output_validation import validate_generated_file
from ovk.core.standard_artifacts import standard_run_manifest


@dataclass(frozen=True)
class StandardOutputPaths:
    """Output paths for a standard OVK run."""

    evidence: Path
    markdown: Path
    attestation: Path
    manifest: Path | None = None
    quality_report: Path | None = None
    envelope: Path | None = None


def write_standard_run_outputs(
    bundle: EvidenceBundle,
    paths: StandardOutputPaths,
    *,
    validate_outputs: bool = True,
) -> None:
    """Write evidence, Markdown, attestation, and optional release support artifacts."""
    markdown = render_bundle_markdown(bundle)
    attestation = bundle_to_statement(bundle)

    evidence_payload = bundle.model_dump(mode="json")
    write_json_file(paths.evidence, evidence_payload)
    paths.markdown.write_text(markdown, encoding="utf-8")
    write_json_file(paths.attestation, attestation)

    if paths.quality_report is not None:
        report = build_evidence_quality_report(bundle)
        write_json_file(paths.quality_report, report.to_dict())

    if validate_outputs:
        evidence_report = validate_generated_file(paths.evidence, "evidence")
        if not evidence_report.valid:
            issues = "; ".join(issue.message for issue in evidence_report.issues)
            raise ValueError(f"evidence bundle failed schema validation: {issues}")
        if paths.quality_report is not None and paths.quality_report.exists():
            quality_report = validate_generated_file(paths.quality_report, "quality_report")
            if not quality_report.valid:
                issues = "; ".join(issue.message for issue in quality_report.issues)
                raise ValueError(f"evidence quality report failed schema validation: {issues}")

    if paths.manifest is not None:
        artifact_paths = [paths.evidence, paths.markdown, paths.attestation]
        if paths.quality_report is not None:
            artifact_paths.append(paths.quality_report)
        manifest_parent = paths.manifest.parent.resolve()
        manifest_root = None
        try:
            if all(path.resolve().is_relative_to(manifest_parent) for path in artifact_paths):
                manifest_root = manifest_parent
        except ValueError:
            manifest_root = None
        manifest = standard_run_manifest(
            evidence_path=paths.evidence,
            markdown_path=paths.markdown,
            attestation_path=paths.attestation,
            quality_report_path=paths.quality_report,
            root=manifest_root,
        )
        write_json_file(paths.manifest, manifest)
        envelope_path = paths.envelope or paths.manifest.parent / "ovk-attestation-envelope.json"
        envelope = build_attestation_envelope(statement=attestation, manifest_path=paths.manifest)
        write_json_file(envelope_path, envelope)
