# Sprint 5 Release Metadata Update

Sprint 5 now includes machine-readable release metadata.

Implemented:

- Added `ovk.core.release_metadata`.
- Added `tests/test_release_metadata.py`.
- Added `scripts/show_release_metadata.py`.

The metadata records the v0.1 release candidate, supported commands, supported evidence lanes, and optional backends.

This gives maintainers a small package-level source of truth for release notes and tagging checks.
