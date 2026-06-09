# Sprint 3 Authorization CLI Update

This note supplements `docs/AUTHORIZATION_OBLIGATION_RUNNER.md` and `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added first-class `ovk auth-obligation` support.
- Added tests in `tests/test_auth_obligation_cli.py`.
- The command writes evidence, Markdown, and attestation outputs.
- The command uses the validated authorization path, so malformed route abstractions produce `unknown` and `require_human_review`.

## Preferred command

```bash
ovk auth-obligation \
  examples/auth_regression/input_admin_bypass.json \
  --repo example/repo \
  --head-sha demo-head \
  --evidence-output ovk-auth-evidence.json \
  --markdown-output ovk-auth-comment.md \
  --attestation-output ovk-auth-attestation.json \
  --advisory
```

## Malformed-input command

```bash
ovk auth-obligation \
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

- Route the stable authorization adapter through the validated obligation-backed path when safe.
- Wire the authorization obligation benchmark scorer into CI when workflow edits are permitted.
