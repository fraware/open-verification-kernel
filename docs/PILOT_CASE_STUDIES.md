# OVK Pilot Case Studies

Structured outcomes from the v1.0 pilot manifests in `examples/pilot_repos/`. Metrics are measured on a developer workstation (Windows 11, Python 3.11) using `ovk check` and `ovk verify` in advisory mode.

## Pilot Zero: In-repo dogfood (external consumer simulation)

**Workflow:** `.github/workflows/pilot-dogfood.yml` (weekly + `workflow_dispatch`)

**Manifest:** `examples/pilot_repos/external_oss_ci_secrets.json`

**Consumer path:** local Action (`./`) with `OVK_PACKAGE_VERSION: "1.1.0"` to mirror fork adopters pinning `@v1.1.0` and PyPI install.

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory mode | yes | yes |
| Unsafe workflow diff block rate | 100% | _from weekly artifact_ |
| Safe manifest pass rate | 100% | _from weekly artifact_ |
| False positive rate (fixtures) | 0% | _from pilot-metrics.json_ |
| Median manifest latency | — | _from pilot-metrics.json_ |
| Adoption summary | published | `docs/benchmarks/adoption-summary.json` |

**Artifacts:** `pilot-dogfood-metrics` workflow artifact (`pilot-report.json`, `pilot-metrics.json`, `ovk-evidence.json`, `pilot-dogfood-bundle/`).

**Reproduction:**

```bash
ovk pilot --output pilot-report.json
python scripts/collect_pilot_metrics.py --pilot-report pilot-report.json --source pilot_dogfood --ovk-version 1.1.0 --output pilot-metrics.json
python scripts/render_pilot_metrics.py --pilot-metrics pilot-metrics.json
```

**Notes:** Pilot Zero is the in-repo maximum deliverable before community OSS repos complete advisory rollout. Metrics feed `docs/benchmarks/adoption-summary.json` via `scripts/render_pilot_metrics.py`.

## Pilot 1: Self-protection only

**Manifest:** `examples/pilot_repos/self_protection_only.json`

| Metric | Result |
|--------|--------|
| Time to first green run | ~0.3s |
| Lanes executed | 1 |
| False positive rate (fixtures) | 0% (1/1 pass case) |
| Cost per PR (local) | No external binaries |

**Notes:** Lowest-friction adoption path for OSS repos adding agent-authored PR gates.

## Pilot 2: CI secrets only

**Manifest:** `examples/pilot_repos/ci_secrets_only.json`

| Metric | Result |
|--------|--------|
| Time to first green run | ~0.2s |
| Lanes executed | 1 |
| Block rate on unsafe workflow diff | 100% (`workflow_secrets_on_pr.diff`) |
| Repair hint class | `remove_untrusted_secret_usage` |

## Pilot 3: Full MVP

**Manifest:** `examples/pilot_repos/full_mvp.json`

| Metric | Result |
|--------|--------|
| Time to green (all pass fixtures) | ~2.1s |
| Lanes executed | 5 |
| False positive rate (fixtures) | 0% (5/5 pass cases) |
| Bundle artifacts | evidence, markdown, attestation, manifest, quality |

## Pilot 4: Wave-1 backends

**Manifest:** `examples/pilot_repos/wave1_backends.json`

| Metric | Result |
|--------|--------|
| Backends exercised | Cedar, TLA+, Kani |
| Deterministic fallback | 100% (no native binaries required) |
| p95 case latency (bench) | &lt;30ms per backend fixture |

## Pilot 5: Wave-2 backends

**Manifest:** `examples/pilot_repos/wave2_backends.json`

| Metric | Result |
|--------|--------|
| Backends exercised | Dafny, Verus, Lean, CBMC, Alloy |
| Router surface selection | File-type bonuses verified in FormalPR-Bench routing cases |
| Bench pass rate | 100% on canonical + extended cases |

## Multi-surface PR check

**Fixture:** `examples/multi_surface/pr_combined.diff`

| Metric | Result |
|--------|--------|
| `ovk check` latency | ~130ms |
| Lanes triggered | 4 |
| Merge recommendation | `block` |
| Intent recall (bench) | 4/4 expected intents |

## Reproduction

```bash
ovk pilot
ovk verify --manifest examples/pilot_repos/full_mvp.json --advisory
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json
```

## External pilots

Template playbook: [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md)

Manifest template: [templates/pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json)

| Pilot | Status | Lane | Advisory period | False positive rate | Strict enabled |
|-------|--------|------|-----------------|---------------------|----------------|
| _Pending community repo_ | recruiting | ci_secrets | — | — | no |

When an external OSS repo completes advisory rollout, add a row with measured metrics (PRs evaluated, block rate on known-bad diffs, median `ovk check` latency, false positive rate). Target: &lt;5% false positives before enabling strict on protected branches.

Example advisory metrics to publish:

| Metric | Target |
|--------|--------|
| PRs evaluated (2 weeks) | ≥10 |
| Block rate on unsafe workflow diff | 100% |
| False positive rate | &lt;5% |
| Median check latency | &lt;45s |

## External OSS pilots

Template for publishing metrics after an external repository completes the [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) advisory phase. Replace placeholders with measured values.

### Pilot template: External OSS (CI secrets lane)

**Repository:** `org/example-repo` (link to pilot PR or fork)

**Manifest:** `examples/pilot_repos/external_oss_ci_secrets.json` (adapted copy in pilot repo)

**Rollout:** advisory (14 days) → strict on `main`

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory period | ≥14 days | _TBD_ |
| PRs scanned | — | _TBD_ |
| Advisory block rate | — | _TBD_ |
| False positive rate | &lt;5% before strict | _TBD_ |
| Time to first green | — | _TBD_ |
| Strict enable date | — | _TBD_ |
| p95 Action latency | — | _TBD_ |
| Repair hints applied | — | _TBD_ |

**Notes:** _Describe repo surface area, triage outcomes, and any compilation gaps requiring human review._

### Pilot template: External OSS (self-protection lane)

**Repository:** `org/example-repo`

**Manifest:** `examples/pilot_repos/self_protection_only.json`

| Metric | Target | Measured |
|--------|--------|----------|
| Advisory period | ≥14 days | _TBD_ |
| PRs scanned | — | _TBD_ |
| False positive rate | &lt;5% | _TBD_ |
| Agent gate bypass attempts caught | — | _TBD_ |
| Strict enable date | — | _TBD_ |

**Notes:** _Record whether branch-protection metadata was supplied via `check-metadata` or auto-collected._

## Metrics publication checklist

- [ ] Advisory window ≥14 days with artifact retention
- [ ] False-positive rate computed and &lt;5% (or strict not yet enabled)
- [ ] Link to pilot workflow file and OVK version pin (`@v1.1.0`)
- [ ] PR to update this section with measured values (do not ship placeholder `_TBD_` rows)
