# Preflight Report Addendum

Added structured preflight reporting support:

- `ovk.core.preflight`
- `scripts/release_preflight_report.py`
- preflight helper tests
- structured report shape tests

The structured preflight report can also write a JSON report artifact for release archives.

The original `scripts/release_preflight.py` remains in place. An in-place migration was blocked by connector controls.
