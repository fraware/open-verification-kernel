# Migrating OVK

Upgrade paths between major releases. Current version: **v1.2.0**. Adoption checklist: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Upgrade from v1.1.0 to v1.2.0

1. Pin the GitHub Action and PyPI package to `1.2.0`:

```yaml
env:
  OVK_PACKAGE_VERSION: "1.2.0"
jobs:
  ovk:
    permissions:
      contents: read
      checks: write          # required when emit-check: true
      pull-requests: write # required when post-comment: true
    steps:
      - uses: fraware/open-verification-kernel@v1.2.0
        id: ovk
        with:
          mode: advisory
          use-check: "true"
          emit-check: "true"
```

2. Read [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) before switching to strict mode.
3. Use example rollout workflows from `examples/github_workflows/` (advisory → strict).
4. Optional: wire `.verification/config.yml` `default_on_unknown` — now honored on the `ovk check` path ([POLICY.md](POLICY.md)).
5. No evidence bundle schema version changes are required.

Full notes: [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md).

## Upgrade from v1.0.0 to v1.1.0

1. Pin to `1.1.0` (or jump directly to `1.2.0` using the section above).
2. Review [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) before strict mode on protected branches.
3. Optional: `ovk bench --expanded` for the `real_diff` category and repair-loop cases.

Full notes: [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md).

## Upgrade from pre-1.0 builds to v1.0.0

### CLI-first workflow

OVK v1.0 treats the `ovk` CLI as the supported interface. Older `scripts/run_*.py` wrappers emit deprecation warnings.

| Older script | v1.0+ command |
|---------------|--------------|
| `scripts/run_infra_exposure.py` | `ovk infra-exposure` |
| `scripts/run_authorization_obligation.py` | `ovk auth-obligation` |
| `scripts/run_ci_secrets.py` | `ovk ci-secrets` |
| `scripts/run_deployment_state.py` | `ovk deployment-state` |

For pull-request verification, prefer:

```bash
ovk check --changed-files path/to/diff.patch
ovk doctor
ovk bench --expanded
ovk release-preflight
```

### GitHub Action defaults

The composite Action defaults to `ovk check` (`use-check: true`). Strict enforcement via `mode: strict`. v1.2 adds Action outputs (`recommendation`, `exit_code`, `check_emitted`) and reliable strict `emit-check`.

### Backends and routing

Ten optional backends with deterministic fallbacks when native binaries are absent. OVK selects backends from changed file paths. Repository memory under `.verification/memory/` can influence backend preferences.

### Agent and MCP tools

`ovk-mcp` uses the MCP Python SDK when the `mcp` extra is installed. Repair loop: `ovk repair-suggest`, `ovk generate-test`. See [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md).

### Evidence quality

High-risk checks cannot return `allow` without template provenance or an explicit human-review path. v1.2 validates quality reports for all five check types in release readiness checks.

### Benchmarking

```bash
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
```

### Breaking changes from pre-1.0 builds

- Release metadata exposes semver `version` (currently `1.2.0`).
- `ovk bench` is part of release readiness checks.
- Infrastructure diff parsing emits normalized inputs for Terraform hunks.

No schema version changes are required for evidence bundles from older OVK versions.
