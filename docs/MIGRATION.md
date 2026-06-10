# Migrating to OVK v1.1

## Upgrade from v1.0.0 to v1.1.0

1. Pin the GitHub Action and PyPI package to `1.1.0`:

```yaml
env:
  OVK_PACKAGE_VERSION: "1.1.0"
jobs:
  ovk:
    steps:
      - uses: fraware/open-verification-kernel@v1.1.0
        with:
          mode: advisory
          use-check: "true"
```

2. Review [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) before enabling strict mode on protected branches.
3. Optional: run `ovk bench --expanded` to include the new `real_diff` category and repair-loop cases.
4. No schema version changes are required for evidence bundles produced by v1.0 lanes.

Full v1.1.0 notes: [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md).

## Upgrade from v0.1.x or 1.0.0-rc1 to v1.0.0

### CLI-first workflow

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

### GitHub Action defaults

The composite Action defaults to `ovk check` (`use-check: true`) with strict enforcement available via `mode: strict`. Evidence bundles, quality reports, and optional GitHub check emission are written to the configured output directory.

### Backends and routing

v1.0 ships ten optional backends: `opa`, `z3`, `cedar`, `tla+`, `kani`, `dafny`, `verus`, `lean`, `cbmc`, and `alloy`. Each provides a deterministic fallback when native binaries are absent.

Surface-aware routing selects backends from changed file paths (for example `.tf` IAM policies route to Cedar, `.rs` to Kani, `.als` to Alloy). Repository memory under `.verification/memory/` informs router priors across runs.

### Agent and MCP tools

`ovk-mcp` uses the official MCP Python SDK when the optional `mcp` dependency is installed. Agent workflows should call:

- `ovk.compile_obligation`
- `ovk.select_backends`
- `ovk.explain_result`
- `ovk.generate_regression_artifact`

Counterexamples can be converted into regression artifacts with:

```bash
ovk generate-test --evidence ovk-evidence.json
```

### Evidence quality (OVK-INV-005)

High-risk intents inferred at runtime cannot produce an `allow` recommendation unless template provenance is present or human review is explicitly required. Canonical templates under `templates/` include `provenance.source = ovk-template-library`.

### Benchmarking

FormalPR-Bench publishes a multi-dimensional leaderboard JSON artifact:

```bash
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json
```

The expanded 100-case set is available with `ovk bench --expanded`.

### Breaking changes from rc1

- Release metadata exposes `version: 1.0.0` in addition to `release_candidate`.
- `ovk bench` is a supported command and is included in release preflight.
- IaC diff compilation emits normalized `infra` inputs directly for Terraform hunks.

No schema version changes are required for existing evidence bundles produced by v0.1 lanes.
