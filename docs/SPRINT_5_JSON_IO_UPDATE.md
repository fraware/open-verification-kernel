# Sprint 5 JSON IO Update

Sprint 5 now includes shared JSON file helpers.

Implemented:

- Added `ovk.core.json_io`.
- Added `tests/test_json_io.py`.
- Updated `ovk.core.run_outputs` to use `write_json_file`.

This keeps JSON output formatting consistent across standard runner outputs and reduces repeated serialization code.
