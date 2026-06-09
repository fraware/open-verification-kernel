# Sprint 3 Schema Update

This note supplements `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added `schemas/authorization.input.schema.json`.
- Added tests in `tests/test_authorization_input_schema.py`.
- Added `docs/AUTHORIZATION_INPUT_CONTRACT.md`.

## Contract

The authorization route abstraction must include a non-empty `routes` list. Each route must include a path, before and after admin-only booleans, and a `reachable_after` witness list. Each witness must include a non-empty role, and `via` must be a list of strings when supplied.

## Safety rule

Schema failure and runtime validation failure both represent insufficient evidence. The validated authorization path must return `unknown` and `require_human_review`, never `allow`.
