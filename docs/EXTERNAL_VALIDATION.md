# External Validation Matrix

OVK ships a scheduled external validation matrix in `.github/workflows/external-validation.yml` to continuously verify that third-party consumers can run the action in strict and advisory modes.

## What the matrix runs

- `check_strict_block`: runs `uses: ./` with `use-check: "true"` and a failing secrets diff; expected recommendation is `block`.
- `check_advisory_allow`: runs `uses: ./` with preserved gate metadata in advisory mode; expected recommendation is `allow`.
- `mvp_manifest_allow`: runs `uses: ./` with `verification-manifest` (`full_mvp`) in advisory mode; expected recommendation is `allow` and bundle generation.
- `forged_bundle_rejected`: runs `ovk evidence-quality` on an adversarial fixture and requires a failing quality gate.

The workflow also includes:

- `matrix_release_pin`: documents the pinned consumer path (`fraware/open-verification-kernel@v1.1.0`).
- `attestation_smoke`: signed bundle generation (`OVK_SIGNING_KEY`) plus `ovk validate-outputs`.

## Fork procedure

1. Copy `examples/github_workflows/external_consumer.yml` into your fork.
2. Replace local `uses: ./` with a pinned release tag (`uses: fraware/open-verification-kernel@v1.1.0` or newer).
3. Start with advisory mode, verify evidence artifacts, then roll specific repos to strict mode.

## Strict rollout checklist

- Keep `use-check: "true"` for diff-aware routing.
- Start strict mode on high-risk repositories only after advisory baselines are stable.
- Validate generated bundles with `ovk validate-outputs`.
- Keep evidence quality checks enabled for adversarial tampering detection.

## Workflow run history

Use the Actions view for [`External Validation Matrix`](https://github.com/fraware/open-verification-kernel/actions/workflows/external-validation.yml) to inspect weekly runs and scenario artifacts.

## Required permissions

Expected workflow permissions:

- `checks: write`
- `pull-requests: write`
