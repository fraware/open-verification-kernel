"""Helpers for writing standard OVK run outputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ovk.core.attestation import bundle_to_statement
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import write_json_file
from ovk.core.models import EvidenceBundle
from ovk.core.render import render_bundle_markdown
from ovk.core.standard_artifacts import standard_run_manifest


@dataclass(frozen=True)
class StandardOutputPaths:
    """Output paths for a standard OVK run."""

    evidence: Path
    markdown: Path
    attestation: Path
    manifest: Path | None = None
    quality_report: Path | None = None


def write_standard_run_outputs(bundle: EvidenceBundle, paths: StandardOutputPaths) -> None:
    """Write evidence, Markdown, attestation, and optional release support artifacts."""
    markdown = render_bundle_markdown(bundle)
    attestation = bundle_to_statement(bundle)

    write_json_file(paths.evidence, bundle.model_dump(mode="json"))
    paths.markdown.write_text(markdown, encoding="utf-8")
    write_json_file(paths.attestation, attestation)

    if paths.manifest is not None:
        manifest = standard_run_manifest(
            evidence_path=paths.evidence,
            markdown_path=paths.markdown,
            attestation_path=paths.attestation,
        )
        write_json_file(paths.manifest, manifest)

    if paths.quality_report is not None:
        report = build_evidence_quality_report(bundle)
        write_json_file(paths.quality_report, report.to_dict())
