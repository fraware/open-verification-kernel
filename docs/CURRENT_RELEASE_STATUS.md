# Current Release Status

This document summarizes the current release-readiness state after the Sprint 5, Sprint 6, and Sprint 7 cleanup work.

For a fuller assessment of maturity, risks, and remaining sprint work, see `docs/CURRENT_WORK_ASSESSMENT.md`.

## Current package state

- Package metadata is aligned to version `0.1.0`.
- `ovk.__version__` derives from release metadata.
- Release metadata, package metadata, and import-time metadata are checked by a pre-release script.

## Current runner state

- Authorization and infrastructure runners use shared JSON input loading.
- Authorization and infrastructure runners use shared standard output writing.
- Authorization and infrastructure runners use shared recommendation exit-code mapping.
- The infrastructure runner writes an artifact manifest directly.
- The infrastructure runner writes an evidence-quality report directly.
- The authorization runner emits standard evidence, Markdown, and attestation outputs; use the standard manifest wrapper to add a manifest.

## Current evidence-quality state

- `ovk.core.evidence_invariants` checks evidence bundle consistency.
- `scripts/check_evidence_invariants.py` exits non-zero when invariant issues exist.
- `ovk.core.evidence_quality` builds structured quality reports.
- `scripts/write_evidence_quality_report.py` writes JSON quality reports for release archives.
- Standard manifests include quality reports under the `evidence_quality` artifact kind when a standard output path includes a quality report.

## Current preflight state

- `scripts/release_preflight.py` runs metadata, command-surface, and local smoke checks.
- `scripts/release_preflight_report.py` exposes the same preflight structure through a report model and optional JSON report output.
- The local smoke script covers authorization and infrastructure release outputs.

## Known remaining limitations

- GitHub Actions status checks are still not observable through the connector.
- In-place migration of some existing scripts and status documents has been blocked by connector controls.
- Self-protection smoke coverage through the local smoke script remains a follow-up item.
