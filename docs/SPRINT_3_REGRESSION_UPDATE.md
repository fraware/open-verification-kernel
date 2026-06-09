# Sprint 3 Regression Update

This note supplements `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added `scripts/write_authorization_regression.py`.
- The script reads an OVK evidence bundle.
- It extracts authorization counterexamples.
- It writes a pytest regression file using `ovk.adapters.z3.regression`.
- Added `tests/test_write_authorization_regression_script.py`.

## Command

```bash
python scripts/write_authorization_regression.py \
  ovk-auth-evidence.json \
  --output .verification/generated_tests/test_no_admin_route_bypass.py
```

## Behavior

If the evidence bundle contains authorization counterexamples, the generated file contains one pytest test per counterexample. If no counterexamples are present, the generated file records that no authorization counterexamples were available.

## Remaining work

- Add a first-class `ovk` CLI command for the authorization runner.
- Add benchmark cases that score query-polarity preservation and generated regression artifacts.
- Optionally wire the stable authorization adapter through the obligation-backed path.
