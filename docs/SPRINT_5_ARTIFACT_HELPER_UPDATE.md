# Sprint 5 Artifact Helper Update

Sprint 5 now has a shared helper for standard run artifacts.

Implemented:

- Added `ovk.core.standard_artifacts`.
- Added `tests/test_standard_artifacts.py`.
- Updated `scripts/write_standard_run_manifest.py` to use the shared helper.
- Added root-relative manifest coverage for the standard wrapper.
- Updated `scripts/run_infra_exposure.py` to use the shared helper.

This removes duplicated manifest-entry construction for evidence, Markdown, and attestation outputs.
