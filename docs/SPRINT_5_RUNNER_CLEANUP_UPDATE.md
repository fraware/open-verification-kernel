# Sprint 5 Runner Cleanup Update

Sprint 5 now includes runner cleanup and shared helpers.

Implemented:

- Added `ovk.core.exit_codes`.
- Added `tests/test_exit_codes.py`.
- Updated `scripts/run_infra_exposure.py` to use the shared exit-code helper.
- Added `ovk.core.run_outputs`.
- Updated `scripts/run_infra_exposure.py` to use the shared standard output writer.

This reduces duplicated runner logic and keeps process-exit semantics consistent across future runners.
