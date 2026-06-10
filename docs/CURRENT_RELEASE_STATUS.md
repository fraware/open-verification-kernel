# OVK Release Status

Living adoption dashboard for Open Verification Kernel.

**Last updated:** 2026-06-10

## At a glance

| Signal | Current state |
|---|---|
| **Released version** | v1.2.0 (Action pin `@v1.2.0`; PyPI pending maintainer tag — [RELEASE.md](RELEASE.md)) |
| **FormalPR-Bench** | 130/130 pass ([latest summary](benchmarks/latest-leaderboard-summary.json)) |
| **Realistic PR diff score** | 100% ([adoption-summary](benchmarks/adoption-summary.json)) |
| **Check types** | 5 (self-protection, authorization, infrastructure, CI secrets, deployment) |
| **Release readiness** | 12 required checks + 1 optional (`ovk release-preflight`) |
| **Unit tests** | 374 passed, 12 skipped (`pytest`) |
| **CI** | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) on `main` and PRs |
| **External validation** | Weekly — [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md) |

OVK is **not** complete formal verification of arbitrary code. It ships targeted, explainable checks for high-risk PR changes, with explicit unknowns and human-review paths.

## Adoption readiness

| Mode | Safe today? | Notes |
|---|---|---|
| **Advisory** | Yes | Default Action setting — reports findings without failing the job. Start here. |
| **Strict** | Yes, with setup | Use after advisory runs on your repo's diffs. Needs `checks: write` when publishing GitHub check runs. See [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md). |

**Suggested rollout:** advisory only → advisory with check run / PR comment → strict with required check on protected branches.

Machine-readable metrics: [benchmarks/adoption-summary.json](benchmarks/adoption-summary.json).

## Known gaps

Full list: [RELEASE.md — Known limitations](RELEASE.md#known-limitations). Summary:

- Conservative parsing of infrastructure and auth diffs
- Optional native checkers (TLA+, Kani, Dafny, Verus, Lean, Alloy) are informational in CI
- External open-source pilot metrics pending until community repos finish advisory rollout
- Auto-collected branch-protection metadata cannot detect removed required checks without explicit before/after JSON

## Maintainer actions

- Publish v1.2.0 to PyPI and tag the GitHub release ([RELEASE.md](RELEASE.md))
- Recruit external pilots; record outcomes in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md)
- Refresh adoption metrics: `python scripts/render_pilot_metrics.py`

## Recent releases

- **v1.2.0:** Quality checks on all five check types, Action outputs, example workflows, branch-protection guide — [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md)
- **v1.1.0:** Realistic diff benchmark, native checker CI, external rollout guide — [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md)

## Related docs

| Document | Purpose |
|---|---|
| [STATUS.md](STATUS.md) | Capabilities and commands |
| [INTEGRATION.md](INTEGRATION.md) | Install and GitHub Actions |
| [RELEASE.md](RELEASE.md) | Maintainer guide and limitations |
| [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) | Roll out on external repos |
| [BENCHMARK.md](BENCHMARK.md) | FormalPR-Bench |
