# Sprint 5 Metadata Check Update

Sprint 5 now includes a release metadata consistency check.

Implemented:

- Added `scripts/check_release_metadata.py`.
- Added `tests/test_release_metadata_script.py`.
- The check compares package metadata, import-time metadata, and release metadata before tagging.

This gives maintainers a runnable pre-release guard for metadata drift.
