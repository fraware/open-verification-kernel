# OVK Status

Current state of Open Verification Kernel **v1.1.0**.

## Summary

OVK is a solver-agnostic verification kernel for AI-agent pull requests. v1.1 builds on the v1.0 baseline with depth-first improvements: tier-1 native backend CI (OPA, Z3, CBMC), a real-diff benchmark corpus, expanded FormalPR-Bench repair-loop cases, PyPI-pinned GitHub Action installs, and external pilot playbooks.

## Package

- Version `1.1.0` with setuptools package discovery (`ovk*`).
- Optional dependency groups: `dev`, `solvers`, `mcp`, `backends-wave1`, `backends-wave2`.
- Primary command: `ovk check --changed-files <diff>`.
- GitHub Action supports `OVK_PACKAGE_VERSION` for PyPI wheel installs (`open-verification-kernel==1.1.0`).

## Evidence lanes

| # | Property | Autonomous path |
|---|---|---|
| 1 | Self-protection | `ovk check` / `ovk ci` |
| 2 | Authorization | `ovk check` |
| 3 | Infrastructure | `ovk check` |
| 4 | CI secrets | `ovk check` |
| 5 | Deployment approval state | `ovk check` |

Lane details: [LANES.md](LANES.md).

## Backends (10)

`opa`, `z3`, `cedar`, `tla+`, `kani`, `dafny`, `verus`, `lean`, `cbmc`, `alloy` — each with capability manifest and deterministic CI fallback. Tier-1 native jobs (OPA, Z3, CBMC) are required in CI when binaries are installed.

## Key CLI commands

| Command | Purpose |
|---|---|
| `ovk check` | Infer, compile, verify affected lanes from diff or changed files |
| `ovk run` | Execute kernel with routing metadata |
| `ovk doctor` | Environment and layout validation |
| `ovk bench` | FormalPR-Bench + leaderboard artifact |
| `ovk generate-test` | Counterexample → regression artifacts |
| `ovk template list/show/apply` | Template library (100+ intents) |
| `ovk release-preflight` | Structured release readiness checks |
| `ovk-mcp` | MCP SDK server (optional `mcp` extra) |

## Quick commands

```bash
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
ovk release-preflight
python scripts/validate_templates.py
```

## Trust

- HMAC signing via `OVK_SIGNING_KEY`.
- Opt-in Sigstore signing via `OVK_SIGSTORE_SIGNING=1`.
- Evidence quality gate enforces OVK-INV-003/005/008.

## Benchmark

- 34 canonical lane/backend cases + extended routing/adversarial/repair-loop/intent-recall cases.
- 16-case `benchmarks/real_diffs/` corpus for realistic PR diff coverage.
- 100-case expanded set for load coverage.
- Leaderboard schema: `schemas/formal_pr_bench.leaderboard.schema.json`.

## Pilots

In-repo manifests: [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md) and `examples/pilot_repos/`.

External OSS adoption: [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md).

## Migration

Upgrading from v1.0.0: [MIGRATION.md](MIGRATION.md). See [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md).
