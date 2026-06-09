# Sprint 5 JSON IO Update

Sprint 5 now includes shared JSON file helpers.

Implemented:

- Added `ovk.core.json_io`.
- Added `tests/test_json_io.py`.
- Updated `ovk.core.run_outputs` to use `write_json_file`.
- Updated `scripts/run_authorization_obligation.py` to use `read_json_file`.
- Updated `scripts/run_infra_exposure.py` to use `read_json_file`.
- Updated `scripts/write_standard_run_manifest.py` to use `write_json_file`.

This keeps JSON input and output formatting consistent across standard runner and packaging paths and reduces repeated serialization code.

Current limitation:

The attempted `scripts/write_attestation_envelope.py` JSON I/O refactor was blocked by connector controls.
