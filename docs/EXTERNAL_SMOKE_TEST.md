# External Repository Smoke Test

This document defines the smoke test to run once OVK is installed in a separate repository.

## Goal

Validate that the composite Action works outside the OVK repository and produces the expected artifacts and optional PR comment.

## Recommended smoke workflow

Create `.github/workflows/ovk-smoke.yml` in the integration repository:

```yaml
name: OVK Smoke Test

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  ovk-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@main
        with:
          mode: advisory
          backend-strategy: deterministic
          post-comment: "true"
      - uses: actions/upload-artifact@v4
        with:
          name: ovk-smoke-artifacts
          path: |
            ovk-evidence.json
            ovk-pr-comment.md
            ovk-attestation.json
```

## Test cases

### Case 1: no required-check metadata

Open a pull request that touches `.github/workflows/verify.yml` without supplying required-check metadata.

Expected result:

- Action completes in advisory mode.
- Evidence contains `unknown`.
- Recommendation is `require_human_review`.
- A PR comment is posted or updated when permissions allow it.

### Case 2: explicit safe metadata

Provide required-check metadata that preserves `ovk-verify` before and after.

Expected result:

- Evidence contains `pass`.
- Recommendation is `allow`.

### Case 3: removed verification control

Provide required-check metadata where `ovk-verify` appears before the change and is absent after the change.

Expected result:

- Evidence contains `fail`.
- Recommendation is `block`.
- Strict mode would fail the job.

## Acceptance criteria

The smoke test is successful when:

- the Action installs OVK;
- `ovk-evidence.json` is produced;
- `ovk-pr-comment.md` is produced;
- `ovk-attestation.json` is produced;
- advisory mode exits successfully;
- strict mode returns nonzero for `block` or `require_human_review`;
- repeated runs update the existing OVK comment instead of creating duplicates.

## Current caveat

The smoke test should start with `backend-strategy: deterministic`. OPA-backed smoke testing should be added only in an environment where the OPA binary is installed deliberately.
