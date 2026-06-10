# External Validation Matrix

Weekly CI job that verifies external repos can run the OVK GitHub Action in advisory and strict modes.

Scenario definitions: `benchmarks/external_validation/scenarios.json`.

## Scenarios

Scenario IDs (first column) are stable test names in `scenarios.json`. Names such as `mvp_manifest_allow` are historical identifiers; see the **What runs** column for plain-language meaning.

| Scenario | Mode | What runs | Expected |
|---|---|---|---|
| `check_strict_block` | strict | `ovk check` on secrets diff | `block`, job fails |
| `check_strict_emit_check` | strict | `ovk check` + publish check run | `block`, check published |
| `check_advisory_allow` | advisory | `ovk ci` with preserved metadata | `allow`, job passes |
| `external_pilot_advisory` | advisory | `ovk check` on secrets diff | `block` reported, job passes |
| `mvp_manifest_allow` | advisory | Five-check manifest (`full_mvp.json` layout) | `allow`, valid bundle |
| `forged_bundle_rejected` | n/a | Tampered evidence quality gate | rejected |

Also runs:

- **Release pin check** — documents `@v1.2.0` consumer path.
- **Signed bundle smoke** — HMAC signing and `ovk validate-outputs`.

Each scenario asserts the merge recommendation and job exit behavior after the Action runs.

## Fork procedure

1. Copy a workflow from `examples/github_workflows/` (start with `pilot_fork_adopter.yml`).
2. Pin the Action: `uses: fraware/open-verification-kernel@v1.2.0`.
3. Start advisory; move to strict per [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md).

## Strict rollout checklist

- Use `use-check: "true"` for diff-aware analysis.
- Grant `checks: write` when `emit-check: "true"`.
- Enable strict only after advisory baselines are stable.
- Validate bundles with `ovk validate-outputs`.

## Run history

[External Validation Matrix](https://github.com/fraware/open-verification-kernel/actions/workflows/external-validation.yml)

## Permissions

```yaml
permissions:
  contents: read
  checks: write
  pull-requests: write
```
