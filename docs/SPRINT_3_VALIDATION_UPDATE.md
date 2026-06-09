# Sprint 3 Validation Update

This note supplements `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added `ovk.adapters.z3.validation`.
- Added validation for authorization route abstractions.
- Added validation diagnostics for missing routes, missing paths, malformed booleans, malformed witnesses, missing roles, and invalid `via` values.
- Added `ovk.adapters.z3.validation_evidence`.
- Invalid authorization abstractions now produce `unknown` evidence and `require_human_review`.
- Added `ovk.adapters.z3.validated_path`.
- The validated path performs input validation before optional solver execution.
- Updated `scripts/run_authorization_obligation.py` to use the validated path.
- Added malformed authorization fixtures.
- Added tests for validation, validation evidence behavior, and runner-level malformed-input behavior.

## Safety rule

Malformed or incomplete route abstractions must never produce `allow`. Invalid input is an unknown state and requires human review.

## Current validated runner command

```bash
python scripts/run_authorization_obligation.py \
  examples/auth_regression/input_malformed_missing_routes.json \
  --repo example/repo \
  --head-sha demo-head \
  --evidence-output ovk-auth-evidence.json \
  --markdown-output ovk-auth-comment.md \
  --attestation-output ovk-auth-attestation.json \
  --advisory
```

Expected result: `require_human_review`.

## Remaining work

- Add a first-class `ovk` CLI command for the authorization runner.
- Add more adversarial malformed-input benchmark cases.
- Wire the authorization obligation scorer into CI when workflow edits are permitted.
