# External OSS Pilot Playbook

Guide for adding OVK to an external open-source repository: start in advisory mode, measure false positives, then optionally enforce on protected branches.

## Start with one check type

| Check type | Best for | Starter manifest |
|------|----------|------------------|
| CI secrets | Repos with agent-authored workflow PRs | [pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json) |
| Self-protection | Repos adding agent CI gates | `examples/pilot_repos/self_protection_only.json` |

Enable additional check types one at a time after each is stable on your diffs.

## Step 1 — Advisory mode (no merge blocking)

1. Copy `docs/templates/pilot_manifest_ci_secrets.template.json` to `.verification/ci_secrets_pilot.json` in the target repo.
2. Add check input JSON under `.verification/ci_secrets/` (see `examples/ci_secrets/input_secrets_safe.json` for shape).
3. Add OVK to CI in advisory mode. Build the PR diff locally — OVK reads files, not URLs:

```yaml
name: OVK Pilot
on:
  pull_request:
    branches: [main]

env:
  OVK_PACKAGE_VERSION: "1.2.0"

jobs:
  ovk-advisory:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Build PR diff for OVK
        run: |
          git fetch origin "${{ github.base_ref }}"
          git diff "origin/${{ github.base_ref }}...HEAD" > ovk-pr.diff
      - name: OVK advisory check
        uses: fraware/open-verification-kernel@v1.2.0
        with:
          mode: advisory
          use-check: "true"
          changed-files: ovk-pr.diff
          post-comment: "false"
      - name: OVK advisory verify (CI secrets check)
        uses: fraware/open-verification-kernel@v1.2.0
        with:
          mode: advisory
          verification-manifest: .verification/ci_secrets_pilot.json
          bundle-output-dir: ovk-pilot-bundle
          post-comment: "false"
```

4. Run for **two weeks** on all agent PRs without blocking merges.

## Step 2 — Measure

| Metric | Target before strict |
|--------|----------------------|
| False positive rate | under 5% |
| Time to first green after repair | under 5 minutes |
| Block rate on known-bad fixtures | 100% |

Publish results in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md) under **External pilots**.

## Step 3 — Strict on protected branches

When false positives stay below 5%:

```yaml
- uses: fraware/open-verification-kernel@v1.2.0
  with:
    mode: strict
    use-check: "true"
    emit-check: "true"
```

Require the OVK check on `main` / `release/*` only; keep advisory on experimental branches if needed.

## Step 4 — Add more check types

After CI secrets is stable, add check types one at a time using manifests from `examples/pilot_repos/`. Re-run advisory for each new check before strict enforcement.

## Copy-paste workflow

See `examples/github_workflows/pilot_fork_adopter.yml` and the full example in Step 1 above. Upload artifacts for your pilot report:

```yaml
      - uses: actions/upload-artifact@v4
        with:
          name: ovk-pilot-artifacts
          path: |
            ovk-evidence.json
            ovk-pilot-bundle/**
          retention-days: 30
```

## Reference in this repo

Weekly in-repo pilot workflow: `.github/workflows/pilot-dogfood.yml` with `scripts/collect_pilot_metrics.py`.

## Support artifacts

- Repair loop walkthrough: [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md)
- Realistic PR diffs: `benchmarks/real_diffs/`
- Example workflows: `examples/github_workflows/`
- Metrics: `scripts/collect_pilot_metrics.py`, `docs/benchmarks/adoption-summary.json`

## What to report

- Repository name (link)
- Check type(s) enabled
- Advisory duration (dates)
- PRs evaluated / blocked / false positives
- Median `ovk check` latency
- Strict mode enabled (yes/no)

Add entries to [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
