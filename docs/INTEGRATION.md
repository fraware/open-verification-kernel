# OVK Integration Guide

Install and run Open Verification Kernel locally or in GitHub Actions.

Router policy recipes for `.verification/config.yml`: [POLICY.md](POLICY.md).

## Local installation

```bash
pip install -e '.[dev]'
ovk init
ovk release-preflight
```

PyPI (when published): `pip install open-verification-kernel`

Optional Z3: `pip install -e '.[solvers]'`

Optional HMAC signing: `export OVK_SIGNING_KEY=your-signing-secret`

## First demo

Self-protection failing case (gate removed):

```bash
ovk ci --metadata examples/no_agent_self_approval/metadata_gate_removed.json
```

Expected: `block` recommendation, exit code 1 (without `--advisory`).

Passing case:

```bash
ovk ci --metadata examples/no_agent_self_approval/metadata_gate_preserved.json --advisory
```

## GitHub Action

The composite Action in `action.yml` supports advisory and strict modes.

### Modes

| Input | Behavior |
|---|---|
| `mode: advisory` | Writes artifacts; always exits 0 |
| `mode: strict` | Exits nonzero on `block` or `require_human_review` |

### Single-lane (self-protection)

```yaml
name: OVK
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
  checks: read
jobs:
  ovk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@v1.0.0
        with:
          mode: advisory
          use-check: "true"
          backend-strategy: deterministic
          post-comment: "true"
```

Development reference: `uses: ./`

### Multi-lane (all five MVP properties)

```yaml
- uses: fraware/open-verification-kernel@v1.0.0
  with:
    mode: advisory
    verification-manifest: .verification/full_mvp.json
    bundle-output-dir: ovk-release-bundle
```

Adapt `examples/verification_manifests/full_mvp.json` for your repository.

### Action inputs

| Input | Purpose |
|---|---|
| `metadata` | Self-protection metadata JSON |
| `changed-files` | Paths as JSON, newline text, or unified diff |
| `check-metadata` | Required-check metadata JSON |
| `backend-strategy` | `deterministic`, `opa`, or `both` |
| `verification-manifest` | Multi-lane manifest; switches to `ovk verify` |
| `bundle-output-dir` | Output directory for multi-lane bundles |
| `post-comment` | Post or update PR comment |

### Action outputs

**Single-lane:** evidence, Markdown, attestation, manifest, quality report.

**Multi-lane:** above plus provenance and attestation envelope under `bundle-output-dir`.

## Backend strategies

| Value | Meaning |
|---|---|
| `deterministic` | Built-in evaluator (default) |
| `opa` | Optional OPA; missing OPA → human review |
| `both` | Both paths; fail and unknown dominate |

Strict mode uses the deterministic path by default. OPA is opt-in via `backend-strategy`. Missing OPA binaries must never produce `allow`.

## Required-check metadata

Explicit metadata (most reliable):

```json
{
  "before_required_checks": ["unit-tests", "ovk-verify"],
  "after_required_checks": ["unit-tests", "ovk-verify"]
}
```

```yaml
- uses: fraware/open-verification-kernel@v1.0.0
  with:
    check-metadata: ovk-required-checks.json
```

Normalize GitHub branch-protection JSON:

```bash
python scripts/normalize_required_checks.py branch_protection.json --output ovk-required-checks.json
```

Collect via API (best-effort):

```bash
python scripts/collect_branch_metadata.py \
  --repository owner/repo \
  --branch main \
  --output ovk-required-checks.json
```

Missing metadata returns `require_human_review` for high-risk workflow changes — never `allow`.

## External repository smoke test

Create `.github/workflows/ovk-smoke.yml` in an integration repository:

```yaml
name: OVK Smoke Test
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
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
            ovk-artifact-manifest.json
            ovk-evidence-quality.json
```

### Test cases

| Case | Expected |
|---|---|
| Workflow change, no metadata | `require_human_review` |
| Metadata preserves `ovk-verify` | `allow` |
| Metadata removes `ovk-verify` | `block` (strict mode fails job) |
| Multi-lane manifest with passing fixtures | `allow`; full bundle artifacts |

See `examples/github_workflows/external_consumer.yml` for single-lane and multi-lane examples.

## Local commands

```bash
# Default PR verification path
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk doctor

# Multi-lane manifest and pilot program
ovk verify --manifest examples/verification_manifests/full_mvp.json --advisory
ovk pilot

# Benchmark and release gates
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json
ovk release-preflight

# Lane-specific CLIs (focused workflows)
ovk ci --metadata examples/no_agent_self_approval/metadata_gate_preserved.json --advisory
ovk auth-obligation examples/auth_regression/input_admin_bypass.json --advisory
ovk infra-exposure examples/infrastructure_exposure/input_public_sensitive_resource.json --advisory
ovk ci-secrets examples/ci_secrets/input_secrets_exposed.json --advisory
ovk deployment-state examples/deployment_state/input_skipped_approval.json --advisory

# Agent integration
ovk infer --changed-files examples/ci_secrets/workflow_secrets_on_pr.diff
ovk extract-workflow .github/workflows/deploy.yml
ovk-mcp
```

Optional Sigstore signing: set `OVK_SIGSTORE=1` and install cosign. Optional HMAC signing: set `OVK_SIGNING_KEY`.

## Rollout recommendation

1. Advisory mode with `backend-strategy: deterministic`.
2. Supply `check-metadata` or collect branch metadata.
3. Validate artifacts before enabling strict mode.
4. Use `verification-manifest` when all five MVP properties must be checked.

## Policy configuration

Use `.verification/config.yml` to set `mode`, unknown-handling behavior, routing budget, and backend allow/deny lists.

- Schema: `schemas/verification.config.schema.json`
- Recipes: [POLICY.md](POLICY.md)
- Validation: `ovk doctor`
