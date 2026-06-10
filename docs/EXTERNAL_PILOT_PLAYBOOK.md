# External OSS Pilot Playbook

Guide for landing OVK on an external open-source repository with advisory rollout, measured false-positive rate, and optional strict mode on protected branches.

## Scope recommendation

Start with **one lane only**:

| Lane | Best for | Starter manifest |
|------|----------|------------------|
| CI secrets | Repos with agent-authored workflow PRs | [pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json) |
| Self-protection | Repos adding agent CI gates | `examples/pilot_repos/self_protection_only.json` |

Do not enable all five lanes until native/compiler depth is validated on your diffs.

## Phase 0 — Fork and wire advisory mode

1. Copy `docs/templates/pilot_manifest_ci_secrets.template.json` to `.verification/ci_secrets_pilot.json` in the target repo.
2. Add lane input JSON under `.verification/ci_secrets/` (see `examples/ci_secrets/input_secrets_safe.json` for shape).
3. Install OVK in CI (advisory):

```yaml
env:
  OVK_PACKAGE_VERSION: "1.1.0"

- uses: fraware/open-verification-kernel@v1.1.0
  with:
    mode: advisory
    use-check: "true"
    changed-files: ${{ github.event.pull_request.diff_url }}  # or a checked-in diff artifact
```

4. Run for **2 weeks** on all agent PRs without blocking merges.

## Phase 1 — Measure

Track per PR:

| Metric | Target before strict |
|--------|----------------------|
| False positive rate | &lt; 5% |
| Time to first green after repair | &lt; 5 minutes |
| Block rate on known-bad fixtures | 100% |

Publish results in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md) under **External pilots**.

## Phase 2 — Strict on protected branch

When false positives stay below 5%:

```yaml
- uses: fraware/open-verification-kernel@v1.1.0
  with:
    mode: strict
    use-check: "true"
    emit-check: "true"
```

Require the OVK check on `main` / `release/*` only; keep advisory on experimental branches if needed.

## Phase 3 — Expand lanes

After ci_secrets is stable, add lanes one at a time using manifests from `examples/pilot_repos/`. Re-run advisory for each new lane before strict enforcement.

## Fork adopter workflow (copy-paste)

Copy this workflow to `.github/workflows/ovk-pilot.yml` in your repository. It pins the published Action and package version, runs advisory mode for two weeks, and uploads metrics artifacts for your pilot report.

```yaml
name: OVK External Pilot

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write
  checks: write

env:
  OVK_PACKAGE_VERSION: "1.1.0"

jobs:
  ovk-advisory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: OVK advisory check
        uses: fraware/open-verification-kernel@v1.1.0
        with:
          mode: advisory
          use-check: "true"
          changed-files: ${{ github.event.pull_request.diff_url }}
          post-comment: "false"
      - name: OVK advisory verify (CI secrets lane)
        uses: fraware/open-verification-kernel@v1.1.0
        with:
          mode: advisory
          verification-manifest: .verification/ci_secrets_pilot.json
          bundle-output-dir: ovk-pilot-bundle
          post-comment: "false"
      - uses: actions/upload-artifact@v4
        with:
          name: ovk-pilot-artifacts
          path: |
            ovk-evidence.json
            ovk-pilot-bundle/**
          retention-days: 30
```

Starter manifest for the verify step: copy [pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json) to `.verification/ci_secrets_pilot.json` and point `input` at your lane fixture JSON.

In-repo dogfood reference: `.github/workflows/pilot-dogfood.yml` (weekly advisory simulation with `OVK_PACKAGE_VERSION` and `scripts/collect_pilot_metrics.py`).

## Support artifacts

- Repair loop demo: [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md)
- Realistic diff corpus: `benchmarks/real_diffs/`
- External consumer workflow: `examples/github_workflows/external_consumer.yml`
- External OSS manifest: `examples/pilot_repos/external_oss_ci_secrets.json`
- Metrics collector: `scripts/collect_pilot_metrics.py`
- Adoption summary: `docs/benchmarks/adoption-summary.json`

## Reporting template

When publishing pilot metrics, include:

- Repository name (link)
- Lane(s) enabled
- Advisory duration (dates)
- PRs evaluated / blocked / false positives
- Median `ovk check` latency
- Strict mode enabled (yes/no)

Add entries to the **External pilots** section of [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
