# Sprint 3 Adversarial Validation Update

This note supplements `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added additional adversarial validation tests directly in `tests/test_z3_validation.py`.
- Empty route lists are rejected.
- Non-object route entries are rejected.
- Non-boolean route flags are rejected.
- Existing malformed witness tests remain in place.

## Safety rule

The authorization path must treat malformed abstractions as insufficient evidence. These cases must return `unknown` and require human review when evaluated through the validated path.

## Remaining work

- Wire the authorization obligation scorer into CI when workflow edits are permitted.
- Add malformed-input cases to formal benchmark data once connector controls permit additional fixture files.
