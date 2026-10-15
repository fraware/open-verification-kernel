# External OSS Pilot Playbook

Guide for adding OVK to a **consenting** external open-source repository. Start in advisory mode, retain both supported and unsupported PRs, measure reviewer utility and coverage, and qualify strict enforcement only through a separate safety decision.

## Start with one check type

| Check type | Best for | Starter manifest |
|------|----------|------------------|
| CI secrets | Repos with agent-authored workflow PRs | [pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json) |
| Self-protection | Repos adding agent CI gates | `examples/pilot_repos/self_protection_only.json` |

Enable additional check types one at a time after each is stable on your diffs.

**Verified release distinction (2026-10-15):** the examples below pin the exact source commit of the published `v1.2.1` release; the Git tag is unsigned and its GitHub Release is not marked immutable. `OVK_PACKAGE_VERSION: 1.2.1` selects the corresponding older PyPI distribution. New guarantee-continuity reviewer work from draft #218 is **not included**. Read [current release status](CURRENT_RELEASE_STATUS.md) before installing.

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
  OVK_PACKAGE_VERSION: "1.2.1"

jobs:
  ovk-advisory:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # No token write permissions for fork-compatible advisory evaluation.
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Build PR diff for OVK
        run: |
          git fetch origin "${{ github.base_ref }}"
          git diff "origin/${{ github.base_ref }}...HEAD" > ovk-pr.diff
      - name: OVK advisory check
        uses: fraware/open-verification-kernel@a27d5720f4350c00bca34f71d991c31f5a2f38c7
        with:
          mode: advisory
          use-check: "true"
          changed-files: ovk-pr.diff
          post-comment: "false"
      - name: OVK advisory verify (CI secrets check)
        uses: fraware/open-verification-kernel@a27d5720f4350c00bca34f71d991c31f5a2f38c7
        with:
          mode: advisory
          verification-manifest: .verification/ci_secrets_pilot.json
          bundle-output-dir: ovk-pilot-bundle
          post-comment: "false"
```

4. Run for **two weeks** on the organization's natural PR stream, including relevant non-agent changes. Record all eligible and unsupported cases without blocking merges; if the sample is too small, extend the observation window and report attrition.

## Step 2 — Measure

| Measurement | Required reporting |
|--------|--------------------|
| Source-profile coverage | Eligible and unsupported PRs with exact denominators and known blind spots |
| Reviewer judgments | All findings reviewed, disagreements, time spent, independently discovered misses and unknown outcomes |
| Operational cost | Setup effort, per-PR runtime, reviewer minutes, repeat-check and repair work |
| Known-bad controls | All relevant admitted adversarial cases with versioned evidence; never a substitute for real-PR calibration |

**A small pilot demonstrates feasibility, not production accuracy.** Report counts and denominators, rather than treating a threshold such as a 5% false-positive rate from a handful of PRs as sufficient for strict enforcement.

Download the workflow artifact (`ovk-pilot-artifacts`) and ingest metrics into the OVK registry:

```bash
python scripts/ingest_external_pilot_metrics.py --repo org/repo --artifacts-dir ./artifact
python scripts/render_pilot_metrics.py --registry docs/benchmarks/external-pilots-registry.json
```

Optional self-report JSON: copy [external_pilot_report.template.json](templates/external_pilot_report.template.json), fill measured values, and pass `--report external_pilot_report.json` to the ingest script.

Publish results in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md) under **External pilots**.

Registry rows live in [external-pilots-registry.json](benchmarks/external-pilots-registry.json). Existing maintained-consumer reports are not independent customer evaluations.

## Step 3 — Independent strict-enforcement qualification (not an automatic upgrade)

**Do not switch a pilot to strict mode from a low measured false-positive rate alone.** Current generated source profiles are `executable_advisory`, not `externally_calibrated_strict`.

Strict enforcement must be separately authorized by the adopting organization for a *specific exact product version, supported source profile and claim*. Before using any result as a required check, document:

1. Trusted acquisition of the actual repository inputs, source revision, policy and toolchain identities.
2. Source-to-model fidelity for the admitted constructs, together with explicit unsupported, unknown, timeout and error handling.
3. Human-adjudicated normal PRs and adversarial change tests, with denominators, missed issues, false alarms, and uncertainty reported. No arbitrary small-N accuracy threshold.
4. CI token permissions, adversarial fork PR isolation, bypass and workflow-self-modification resistance, protected branch rules, and a rollback owner.
5. Reviewer approval and monitoring for the exact admitted claim family. Unknown and incomplete outcomes do not count as positive verification.

Until those gates are independently met, remain in **advisory mode with no merge-blocking authority**. Green fixture tests do not override this constraint.

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

Published advisory reports (maintained consumers + infra profile): [pilots/README.md](pilots/README.md).

## Support artifacts

- Repair loop walkthrough: [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md)
- Realistic PR diffs: `benchmarks/real_diffs/`
- Example workflows: `examples/github_workflows/`
- Metrics: `scripts/collect_pilot_metrics.py`, `docs/benchmarks/adoption-summary.json`
- External pilot registry: `docs/benchmarks/external-pilots-registry.json`
- Self-report template: `docs/templates/external_pilot_report.template.json`
- Ingest script: `scripts/ingest_external_pilot_metrics.py`

## What to report

- Repository name (link)
- Check type(s) enabled
- Advisory duration (dates)
- PRs evaluated / blocked / false positives
- Median `ovk check` latency
- Strict mode enabled (yes/no)

Add entries to [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
