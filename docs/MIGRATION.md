# Migrating OVK

Upgrade paths between releases. Current package metadata in this tree: **`1.3.0-rc.1`** (engineering candidate). Live signed Action pin: **`v1.2.1`**. Adoption checklist: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Upgrade toward v1.3.0-rc.1 (after attributable tag)

1. Keep advisory mode until you have run your own diffs against the RC pin.
2. Bump Action and package together:

```yaml
env:
  OVK_PACKAGE_VERSION: "1.3.0-rc.1"
jobs:
  ovk:
    permissions:
      contents: read
      checks: write
      pull-requests: write
    steps:
      - uses: fraware/open-verification-kernel@v1.3.0-rc.1
        with:
          mode: advisory
          use-check: "true"
          emit-check: "true"
```

3. Read [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) and [RELEASE_NOTES_v1.3.0-rc.1.md](RELEASE_NOTES_v1.3.0-rc.1.md) before strict mode.
4. Expect stricter honesty around source profiles, support contracts, and fallback policy (`routing.allow_fallback` remains off unless you opt in).
5. Do not treat `v1.2.1` consumer evidence as validation of typed-control-plane commits.

Until the rc.1 tag exists, remain on `@v1.2.1` / `1.2.1` for production pins.

## Upgrade from v1.1.0 to v1.2.0 / v1.2.1

1. Pin the GitHub Action and PyPI package to the signed release you intend (`1.2.1` preferred over `1.2.0`):

```yaml
env:
  OVK_PACKAGE_VERSION: "1.2.1"
jobs:
  ovk:
    permissions:
      contents: read
      checks: write          # required when emit-check: true
      pull-requests: write # required when post-comment: true
    steps:
      - uses: fraware/open-verification-kernel@v1.2.1
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

Full notes: [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md), [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md).

## Upgrade from v1.0.0 to v1.1.0

1. Pin to `1.1.0` (or jump directly to `1.2.1` using the section above).
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

Ten optional backends with deterministic contract paths when native binaries are absent. OVK selects backends from changed file paths. Post-execution strict fallback remains disabled unless policy opts in ([BACKENDS.md](BACKENDS.md), [POLICY.md](POLICY.md)).

### Agent and MCP tools

`ovk-mcp` uses the MCP Python SDK when the `mcp` extra is installed. Repair loop: `ovk repair-suggest`, `ovk generate-test`. See [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md).

### Evidence quality

High-risk checks cannot return `allow` without template provenance or an explicit human-review path. v1.2 validates quality reports for all five check types in release readiness checks.

### Benchmarking

FormalPR-Bench is an internal regression suite (not external calibration):

```bash
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
```

### Breaking changes from pre-1.0 builds

- Release metadata exposes semver `version` (see `pyproject.toml`; this tree uses `1.3.0-rc.1`).
- `ovk bench` is part of release readiness checks.
- Infrastructure diff parsing emits normalized inputs for Terraform hunks.

No schema version changes are required for evidence bundles from older OVK versions.
