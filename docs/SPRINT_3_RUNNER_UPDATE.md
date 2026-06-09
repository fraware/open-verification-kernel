# Sprint 3 Runner Update

This note supplements `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added `scripts/run_authorization_obligation.py`.
- The runner reads an authorization fixture.
- It builds an `AuthorizationObligation`.
- It runs the optional Z3 executor.
- It normalizes the solver result into OVK evidence.
- It builds an evidence bundle.
- It renders a Markdown report.
- It emits an unsigned attestation statement.
- Added `docs/AUTHORIZATION_OBLIGATION_RUNNER.md`.
- Added `tests/test_authorization_obligation_runner.py`.

## Current command

```bash
python scripts/run_authorization_obligation.py \
  examples/auth_regression/input_admin_bypass.json \
  --repo example/repo \
  --head-sha demo-head \
  --evidence-output ovk-auth-evidence.json \
  --markdown-output ovk-auth-comment.md \
  --attestation-output ovk-auth-attestation.json \
  --advisory
```

## Expected behavior

- If a counterexample is found, the recommendation is `block`.
- If no counterexample is found, the recommendation is `allow`.
- If `z3-solver` is unavailable or the solver returns unknown, the recommendation is `require_human_review`.

## Remaining work

- Add a first-class `ovk` CLI command for this runner.
- Add benchmark cases for query-polarity preservation and generated regression artifacts.
- Add direct file emission for generated regression tests.
