# OVK Integration Guide

Check [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) before pinning a version or switching to strict mode.

Install and run Open Verification Kernel locally or in GitHub Actions.

Verification routing configuration for `.verification/config.yml`: [POLICY.md](POLICY.md).

## Local installation

```bash
pip install -e '.[dev]'
ovk init
ovk release-preflight
```

PyPI release (after maintainers publish `v1.2.0`; see [RELEASE.md](RELEASE.md)):

```bash
pip install open-verification-kernel==1.2.0
# optional solvers
pip install "open-verification-kernel[solvers]==1.2.0"
```

Until the wheel is on PyPI, use `pip install -e '.[dev]'` from a checkout or pin the GitHub Action at `@v1.2.0` with `OVK_PACKAGE_VERSION` once published.

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

### Permissions

Copy-paste block for consumer workflows:

```yaml
permissions:
  contents: read
  pull-requests: write   # required when post-comment: true
  checks: write          # required when emit-check: true
```

| Input | Required permission |
|---|---|
| `post-comment: true` | `pull-requests: write` |
| `emit-check: true` | `checks: write` |
| `collect_branch_metadata.py` (auto) | `GITHUB_TOKEN` with repository metadata read |

Fork PRs from outside contributors cannot post comments; keep `post-comment: false` on fork workflows.

### Single check type (self-protection)

```yaml
name: OVK
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
  checks: write
jobs:
  ovk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@v1.2.0
        id: ovk
        with:
          mode: advisory
          use-check: "true"
          emit-check: "true"
          backend-strategy: deterministic
          post-comment: "true"
      - name: Gate on block recommendation
        if: steps.ovk.outputs.recommendation == 'block'
        run: echo "OVK reported block; review artifacts before merge"
```

Development reference: `uses: ./`

### All five check types (manifest)

```yaml
- uses: fraware/open-verification-kernel@v1.2.0
  with:
    mode: advisory
    verification-manifest: .verification/full_mvp.json
    bundle-output-dir: ovk-release-bundle
```

Adapt `examples/verification_manifests/full_mvp.json` (standard five-check manifest) for your repository.

### Action inputs

| Input | Purpose |
|---|---|
| `metadata` | Self-protection metadata JSON |
| `changed-files` | Paths as JSON, newline text, or unified diff |
| `check-metadata` | Required-check metadata JSON |
| `backend-strategy` | `deterministic`, `opa`, or `both` |
| `verification-manifest` | Five-check manifest; switches to `ovk verify` |
| `bundle-output-dir` | Output directory for multi-check bundles |
| `post-comment` | Post or update PR comment |
| `emit-check` | Emit GitHub check run named **Open Verification Kernel** |
| `use-check` | Run `ovk check` instead of `ovk ci` (ignored when `verification-manifest` is set) |

When `verification-manifest` is set, the manifest path wins over `use-check`.

### Action outputs

| Output | Meaning |
|---|---|
| `recommendation` | Merge recommendation from `ovk-evidence.json` |
| `exit_code` | `0` allow, `1` block, `2` require_human_review |
| `check_emitted` | `true` when `emit-check` successfully posted a check run |

Downstream example:

```yaml
- uses: fraware/open-verification-kernel@v1.2.0
  id: ovk
  with:
    mode: strict
    use-check: "true"
    emit-check: "true"
- name: Fail when OVK blocks
  if: steps.ovk.outputs.recommendation == 'block'
  run: exit 1
```

**Artifact files:**

**Single check type:** evidence, Markdown, attestation, manifest, quality report.

**All check types (manifest):** above plus provenance and attestation envelope under `bundle-output-dir`.

### emit-check behavior

| Mode | emit-check failure |
|---|---|
| `advisory` | Job continues; `check_emitted` is `false` |
| `strict` | Job fails when check run cannot be emitted |

GitHub check conclusion mapping:

| Recommendation | Check conclusion | Strict exit code |
|---|---|---|
| `allow` | `success` | 0 |
| `block` | `failure` | 1 |
| `require_human_review` | `neutral` | 2 |

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
- uses: fraware/open-verification-kernel@v1.2.0
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

**Precedence:** explicit `check-metadata` input wins over auto-collected `ovk-branch-metadata.json`. Auto-collected metadata sets identical before/after required checks and cannot detect check **removal** without explicit before/after JSON.

Example fixtures with explicit before/after:

- `examples/no_agent_self_approval/check_metadata_gate_removed.json`
- `examples/no_agent_self_approval/check_metadata_github_shape_removed.json`

## Branch protection setup

Required GitHub check name: **`Open Verification Kernel`** (from `ovk/core/github_check.py`).

### Rollout stages

| Stage | Workflow example | Mode | Publish check run | Branch protection |
|---|---|---|---|---|
| 1 — Advisory only | `examples/github_workflows/pilot_fork_adopter.yml` | advisory | no | none |
| 2 — Advisory + visibility | `examples/github_workflows/pilot_advisory_with_comment.yml` | advisory | yes | optional |
| 3 — Strict enforcement | `examples/github_workflows/external_consumer.yml` | strict | yes | required on `main` |
| 4 — Required check wired | `examples/github_workflows/branch_protection_required_check.yml` | strict | yes | required check |

Steps for strict enforcement:

1. Run strict + `emit-check: true` on a sample PR and confirm the check appears on the commit.
2. In repository **Settings → Branches**, add **`Open Verification Kernel`** as a required status check on protected branches.
3. Supply explicit `check-metadata` when verifying gate preservation (auto-collected metadata is best-effort only).

`collect_branch_metadata.py` needs a `GITHUB_TOKEN` with permission to read branch protection rules. Pass explicit before/after JSON when you need removal detection.

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
  checks: write
jobs:
  ovk-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@v1.2.0
        env:
          OVK_PACKAGE_VERSION: "1.2.0"
        with:
          mode: advisory
          use-check: "true"
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
| Five-check manifest with passing fixtures | `allow`; full bundle artifacts |

See example rollout workflows under `examples/github_workflows/`:

- `pilot_fork_adopter.yml` — advisory manifest only
- `pilot_advisory_with_comment.yml` — advisory with check run and PR comment
- `external_consumer.yml` — strict enforcement
- `branch_protection_required_check.yml` — required-check wiring

## Local commands

```bash
# Default PR verification path
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk doctor

# Five-check manifest and pilot program
ovk verify --manifest examples/verification_manifests/full_mvp.json --advisory
ovk pilot

# Benchmark and release readiness
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json
ovk release-preflight

# Focused CLIs (one check type at a time)
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

Optional Sigstore signing: set `OVK_SIGSTORE_SIGNING=1` and install cosign. Optional HMAC signing: set `OVK_SIGNING_KEY`.

## Repair loop

After a blocked `ovk check`, extract machine-readable repair hints:

```bash
ovk check --changed-files examples/repair_loops/ci_secrets/failing.diff --output-dir .ovk-check
ovk repair-suggest --evidence .ovk-check/ovk-evidence.json
```

See [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md) for repair-loop demos and MCP session flow.

## Rollout recommendation

1. Advisory mode with `backend-strategy: deterministic`.
2. Supply `check-metadata` or collect branch metadata.
3. Validate artifacts before enabling strict mode.
4. Use `verification-manifest` when all five check types must run together.

## Policy configuration

Use `.verification/config.yml` to set `mode`, unknown-handling behavior, routing budget, and backend allow/deny lists.

- Schema: `schemas/verification.config.schema.json`
- Configuration examples: [POLICY.md](POLICY.md)
- Validation: `ovk doctor`

OVK reads `default_on_unknown` when building merge recommendations via `ovk check` and related diff-based commands. Focused per-check commands use the default (`require_human_review`) unless you pass policy through a custom integration.

## Older wrapper scripts

OVK v1.0+ treats the `ovk` CLI as the supported interface. Deprecated scripts under `scripts/run_*.py` remain for compatibility and emit warnings on stderr. Each script flag maps 1:1 to its `ovk` command (`--quality-output` → `--quality-output`, `--advisory`, output paths, etc.). See [MIGRATION.md](MIGRATION.md) for the mapping table.
