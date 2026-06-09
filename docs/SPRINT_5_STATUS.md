# Sprint 5 Status

Sprint 5 focuses on release hardening for OVK v0.1.

## Goal

Make OVK outputs reproducible, auditable, and easier to consume in CI and review workflows.

## Completed so far

- Added `ovk.core.artifact_manifest`.
- Added deterministic SHA-256 artifact entries.
- Added `scripts/write_artifact_manifest.py`.
- Added artifact manifest tests.
- Added `docs/ARTIFACT_MANIFEST.md`.

## Current manifest semantics

- Each artifact entry records path, kind, SHA-256 digest, and byte size.
- Entries are sorted deterministically by kind and path.
- The manifest does not include wall-clock timestamps.

## Remaining Sprint 5 work

1. Integrate manifest writing into runner scripts.
2. Add an attestation envelope that references the artifact manifest.
3. Add a release artifact layout guide.
4. Add example repository workflow documentation.
5. Add v0.1 readiness checklist.

## Engineering rule

Release artifacts must be reproducible and hash-addressable. A manifest should describe bytes actually written to disk, not intended outputs.
