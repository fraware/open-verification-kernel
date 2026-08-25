# OVK Pilot Case Studies

Measured outcomes from example configurations in `examples/pilot_repos/`. Metrics use `ovk check` and `ovk verify` in advisory mode.

**Honesty:** in-repo pilot dogfood is **not** independent consumer validation and does not authorize `verified_source_sha` or `externally_calibrated_strict`. Live signed pin for external remotes remains `v1.2.1` until `v1.3.0-rc.1` is attributable.

## In-repo reference pilot

Simulates how an external repo would consume OVK before community pilots land.

**Workflow:** `.github/workflows/pilot-dogfood.yml` — weekly in-repo pilot run (filename is historical; manual trigger supported)

**Manifest:** `examples/pilot_repos/external_oss_ci_secrets.json`

**Consumer path:** local Action (`./`) with package version matching the workflow under test. Prefer mirroring `@v1.2.1` for live signed pins; bump only after an attributable RC tag.

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory mode | yes | yes |
| Unsafe workflow diff block rate | 100% | _from weekly artifact_ |
| Safe manifest pass rate | 100% | _from weekly artifact_ |
| False positive rate (fixtures) | 0% | _from pilot-metrics.json_ |
| Median manifest latency | — | _from pilot-metrics.json_ |
| Adoption summary | published | `docs/benchmarks/adoption-summary.json` |

**Reproduction:**

```bash
ovk pilot --output pilot-program-report.json
python scripts/collect_pilot_metrics.py \
  --pilot-report pilot-dogfood-report.json \
  --input-pilot-report pilot-program-report.json \
  --source pilot-dogfood \
  --ovk-version 1.2.0
python scripts/render_pilot_metrics.py --metrics pilot-dogfood-report.json
```

`pilot-dogfood` in `--source` and report filenames matches the historical workflow name; metrics land in `docs/benchmarks/adoption-summary.json` under the `pilot_dogfood` schema field.

## Self-protection only

**Manifest:** `examples/pilot_repos/self_protection_only.json`

| Metric | Result |
|--------|--------|
| Time to first green run | ~0.3s |
| Check types run | 1 |
| False positive rate (fixtures) | 0% (1/1 pass case) |

Lowest-friction path for repos adding agent-authored PR gates.

## CI secrets only

**Manifest:** `examples/pilot_repos/ci_secrets_only.json`

| Metric | Result |
|--------|--------|
| Time to first green run | ~0.2s |
| Block rate on unsafe workflow diff | 100% |
| Suggested fix class | `remove_untrusted_secret_usage` |

## All five check types

**Manifest:** `examples/verification_manifests/full_mvp.json` — standard five-check manifest (same layout as `examples/pilot_repos/full_mvp.json`)

| Metric | Result |
|--------|--------|
| Time to green (all pass fixtures) | ~2.1s |
| Check types run | 5 |
| False positive rate (fixtures) | 0% (5/5 pass cases) |
| Artifacts | evidence, markdown, attestation, manifest, quality report |

## Cedar, TLA+, and Kani backends

**Manifest:** `examples/pilot_repos/wave1_backends.json` — Cedar, TLA+, and Kani subset

| Metric | Result |
|--------|--------|
| Backends exercised | Cedar, TLA+, Kani |
| Works without native binaries | yes (built-in fallback) |
| p95 latency per fixture | under 30ms |

## Dafny, Verus, Lean, CBMC, and Alloy backends

**Manifest:** `examples/pilot_repos/wave2_backends.json` — Dafny, Verus, Lean, CBMC, and Alloy subset

| Metric | Result |
|--------|--------|
| Backends exercised | Dafny, Verus, Lean, CBMC, Alloy |
| File-type routing | verified in benchmark routing cases |
| Bench pass rate | 100% on canonical + extended cases |

## Multi-surface PR

**Fixture:** `examples/multi_surface/pr_combined.diff`

| Metric | Result |
|--------|--------|
| `ovk check` latency | ~130ms |
| Check types triggered | 4 |
| Merge recommendation | `block` |
| Expected checks recalled | 4/4 |

## Reproduction

```bash
ovk pilot
ovk verify --manifest examples/verification_manifests/full_mvp.json --advisory
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json
```

## External pilots

Playbook: [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md)

Manifest template: [templates/pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json)

Published advisory reports (OVK-PR8): [pilots/README.md](pilots/README.md)

### Active and recruiting

Source of truth: [external-pilots-registry.json](benchmarks/external-pilots-registry.json) (merged into [adoption-summary.json](benchmarks/adoption-summary.json) by `scripts/render_pilot_metrics.py`).

| Repository | Status | Kind | Check types | Advisory period | False positive rate | Strict enabled |
|-------|--------|------|-------------|-----------------|---------------------|----------------|
| [fraware/ovk-consumer-fastapi-terraform](pilots/fastapi-terraform/REPORT.md) | advisory | Maintained consumer | ci_secrets, infrastructure | 2026-07-11 – 2026-07-25 | 0.0 (fixtures) | no |
| [fraware/ovk-consumer-express-actions](pilots/express-actions/REPORT.md) | advisory | Maintained consumer | ci_secrets, self_protection | 2026-07-11 – 2026-07-25 | 0.0 (fixtures) | no |
| [in-repo/ovk-pilot-infra-terraform-k8s](pilots/infra-terraform-k8s/REPORT.md) | advisory | In-repo maintained profile | infrastructure, ci_secrets | 2026-07-11 – 2026-07-25 | 0.0 (fixtures) | no |
| TBD - recruiting first true external OSS adopter | recruiting | True external OSS (open) | ci_secrets | — | — | no |

Maintained-consumer and in-repo profile rows are **fixture/dogfood** measurements with `strict_mode_recommendation: remain_advisory`. They do not replace a true independent external OSS adopter. When such a repo completes advisory rollout, ingest artifacts, update the registry, re-render the adoption summary, and keep the kind label explicit. Target: under 5% false positives before enabling strict mode on protected branches.

### Reporting template

**Repository:** `org/example-repo` (link to pilot PR or fork)

**Manifest:** adapted from `examples/pilot_repos/external_oss_ci_secrets.json` or `self_protection_only.json`

**Rollout:** advisory (at least 14 days) → strict on `main`

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory period | ≥14 days | _TBD_ |
| PRs scanned | — | _TBD_ |
| Block rate on unsafe workflow diff | 100% | _TBD_ |
| False positive rate | <5% before strict | _TBD_ |
| Time to first green after repair | <5 minutes | _TBD_ |
| Strict enable date | — | _TBD_ |
| p95 Action latency | — | _TBD_ |
| Repair hints applied | — | _TBD_ |

### Publication checklist

- [ ] Advisory window ≥14 days with artifact retention
- [ ] False-positive rate computed and under 5% (or strict not yet enabled)
- [ ] Link to workflow file and version pin (`@v1.2.1` live; `@v1.3.0-rc.1` after attributable cut)
- [ ] Update the **Active and recruiting** table with measured values
