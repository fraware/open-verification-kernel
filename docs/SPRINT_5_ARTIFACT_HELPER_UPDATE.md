# Sprint 5 Artifact Helper Update

Sprint 5 now has shared helpers for standard run artifacts and standard run outputs.

Implemented:

- Added `ovk.core.standard_artifacts`.
- Added `tests/test_standard_artifacts.py`.
- Updated `scripts/write_standard_run_manifest.py` to use the shared helper.
- Added root-relative manifest coverage for the standard wrapper.
- Updated `scripts/run_infra_exposure.py` to use the shared artifact helper.
- Added `ovk.core.run_outputs`.
- Added `tests/test_run_outputs.py`.
- Refactored `scripts/run_infra_exposure.py` to use `write_standard_run_outputs`.

This removes duplicated manifest-entry construction and duplicated evidence, Markdown, attestation, and manifest serialization from the infrastructure runner.
