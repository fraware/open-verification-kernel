# OVK Pilot Case Studies

Measured outcomes from example configurations in `examples/pilot_repos/`. Metrics use `ovk check` and `ovk verify` in advisory mode.

**Honesty:** in-repo pilot dogfood is **not** independent consumer validation and does not authorize `verified_source_sha` or `externally_calibrated_strict`. Fixture pass/block output does not establish a false-positive rate; unadjudicated error rates are reported as unknown. The last published tag is `v1.2.1`, whose annotated Git tag was reported unsigned by GitHub on 2026-10-15; do not call it a Git-signed or protected pin. For any permitted external advisory experiment, use a reviewed **full 40-hex commit SHA** and independently verify applicable release assets and operator trust.

## In-repo reference pilot

Simulates how an external repo would consume OVK before community pilots land.

**Workflow:** `.github/workflows/pilot-dogfood.yml` — weekly in-repo pilot run (filename is historical; manual trigger supported)

**Manifest:** `examples/pilot_repos/external_oss_ci_secrets.json`

**Consumer path:** local Action (`./`) with package version matching the workflow under test. Prefer the audited commit SHA `a27d5720f4350c00bca34f71d991c31f5a2f38c7` behind the published `v1.2.1` annotated tag for a legacy advisory Action example, with explicit owner review. This pins code identity but does not independently verify signer, source semantics, or dependency integrity. Bump only after an attributable new release.

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory mode | yes | yes |
| Unsafe workflow diff block rate | 100% | _from weekly artifact_ |
| Safe manifest pass rate | 100% | _from weekly artifact_ |
| Adjudicated false-positive rate | — | Unknown; the fixture outcomes contain no independent reviewer labels |
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
| Adjudicated false-positive rate | Unknown; one passing fixture is not independent error adjudication |

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
| Adjudicated false-positive rate | Unknown; five passing fixtures are not independent error adjudication |
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
| [fraware/ovk-consumer-fastapi-terraform](pilots/fastapi-terraform/REPORT.md) | advisory | Maintained consumer | ci_secrets, infrastructure | 2026-07-11 – 2026-07-25 | unknown (unadjudicated fixtures) | no |
| [fraware/ovk-consumer-express-actions](pilots/express-actions/REPORT.md) | advisory | Maintained consumer | ci_secrets, self_protection | 2026-07-11 – 2026-07-25 | unknown (unadjudicated fixtures) | no |
| [in-repo/ovk-pilot-infra-terraform-k8s](pilots/infra-terraform-k8s/REPORT.md) | advisory | In-repo maintained profile | infrastructure, ci_secrets | 2026-07-11 – 2026-07-25 | unknown (unadjudicated fixtures) | no |
| TBD - recruiting first true external OSS adopter | recruiting | True external OSS (open) | ci_secrets | — | — | no |

Maintained-consumer and in-repo profile rows are **fixture/dogfood** measurements with `strict_mode_recommendation: remain_advisory`. They do not replace a true independent external OSS adopter. When such a repo completes advisory rollout, ingest artifacts, update the registry, re-render the adoption summary, and keep the kind label explicit. No numeric fixture-rate threshold authorizes strict enforcement. The formerly displayed 0.0 error rates were not independently adjudicated and are now null in the registry and adoption summary; historical values remain in Git history. An independent pilot needs explicit, reviewed false-positive and false-negative denominators, coverage and unknown handling.

### Reporting template

**Repository:** `org/example-repo` (link to pilot PR or fork)

**Manifest:** adapted from `examples/pilot_repos/external_oss_ci_secrets.json` or `self_protection_only.json`

**Rollout:** advisory (at least 14 days) → independent review of qualified source coverage, sample adequacy, unknowns, false negatives, false positives, governance and rollback → optional separately approved strict deployment. There is no automatic promotion based on elapsed time or one metric.

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory period | ≥14 days | _TBD_ |
| PRs scanned | — | _TBD_ |
| Block rate on unsafe workflow diff | 100% | _TBD_ |
| False-positive numerator/denominator and uncertainty | report all cases; no automatic strict threshold from small N | _TBD_ |
| Time to first green after repair | <5 minutes | _TBD_ |
| Strict enable date | — | _TBD_ |
| p95 Action latency | — | _TBD_ |
| Repair hints applied | — | _TBD_ |

### Publication checklist

- [ ] Advisory window ≥14 days with artifact retention
- [ ] Report false positives with denominator and sampling limitations; strict remains off until independent source-profile, sensitivity/false-negative and policy qualification
- [ ] Link to workflow file and exact immutable commit SHA; do not rely on unprotected release tags as immutable installation pins
- [ ] Update the **Active and recruiting** table with measured values
