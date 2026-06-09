# Sprint 3 Schema Coverage Update

The authorization schema test suite has been expanded.

Implemented:

- Added `tests/test_authorization_input_schema_extra.py`.
- Covered empty route lists.
- Covered missing route paths.
- Covered missing `reachable_after` fields.
- Covered non-object witness entries.

This keeps the JSON schema aligned with the runtime validator: malformed route abstractions should fail before they can support a passing authorization claim.
