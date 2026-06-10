# OVK Pilot Case Studies

Structured outcomes from the v1.0 pilot manifests in `examples/pilot_repos/`. Metrics are measured on a developer workstation (Windows 11, Python 3.11) using `ovk check` and `ovk verify` in advisory mode.

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
