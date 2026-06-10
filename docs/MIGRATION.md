# Migrating to OVK v1.0

This guide covers upgrades from OVK v0.1.x and `1.0.0-rc1` to **v1.0.0**.

## CLI-first workflow

OVK v1.0 treats the `ovk` CLI as the supported interface. Legacy maintainer scripts under `scripts/run_*.py` remain for compatibility but emit deprecation warnings.

| Legacy script | v1.0 command |
|---------------|--------------|
| `scripts/run_infra_exposure.py` | `ovk infra-exposure` |
| `scripts/run_authorization_obligation.py` | `ovk auth-obligation` |
| `scripts/run_ci_secrets.py` | `ovk ci-secrets` |
| `scripts/run_deployment_state.py` | `ovk deployment-state` |

For pull-request verification, prefer:

```bash
ovk check --changed-files path/to/diff.patch
ovk doctor
ovk bench
ovk release-preflight
```

## GitHub Action defaults

The composite Action now defaults to `ovk check` (`use-check: true`) with strict enforcement available via `mode: strict`. Evidence bundles, quality reports, and optional GitHub check emission are written to the configured output directory.

## Backends and routing

v1.0 ships ten optional backends: `opa`, `z3`, `cedar`, `tla+`, `kani`, `dafny`, `verus`, `lean`, `cbmc`, and `alloy`. Each provides a deterministic fallback when native binaries are absent.

Surface-aware routing selects backends from changed file paths (for example `.tf` IAM policies route to Cedar, `.rs` to Kani, `.als` to Alloy). Repository memory under `.verification/memory/` informs router priors across runs.

## Agent and MCP tools

`ovk-mcp` uses the official MCP Python SDK when the optional `mcp` dependency is installed. Agent workflows should call:

- `ovk.compile_obligation`
- `ovk.select_backends`
- `ovk.explain_result`
- `ovk.generate_regression_artifact`

Counterexamples can be converted into regression artifacts with:

```bash
ovk generate-test --evidence ovk-evidence.json
```

## Evidence quality (OVK-INV-005)

High-risk intents inferred at runtime cannot produce an `allow` recommendation unless template provenance is present or human review is explicitly required. Canonical templates under `templates/` include `provenance.source = ovk-template-library`.

## Benchmarking

FormalPR-Bench now publishes a multi-dimensional leaderboard JSON artifact:

```bash
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json
```

The expanded 100-case set is available with `ovk bench --expanded`.

## Breaking changes from rc1

- Release metadata exposes `version: 1.0.0` in addition to `release_candidate`.
- `ovk bench` is a new supported command and is included in release preflight.
- IaC diff compilation emits normalized `infra` inputs directly for Terraform hunks.

No schema version changes are required for existing evidence bundles produced by v0.1 lanes.
