# External OSS Pilot Playbook

Guide for landing OVK on an external open-source repository with advisory rollout, measured false-positive rate, and optional strict mode on protected branches.

## Scope recommendation

Start with **one lane only**:

| Lane | Best for | Starter manifest |
|------|----------|------------------|
| CI secrets | Repos with agent-authored workflow PRs | [pilot_manifest_ci_secrets.template.json](templates/pilot_manifest_ci_secrets.template.json) |
| Self-protection | Repos adding agent CI gates | `examples/pilot_repos/self_protection_only.json` |

Do not enable all five lanes until native/compiler depth is validated on your diffs.

## Phase 0 — Fork and wire advisory mode

1. Copy `docs/templates/pilot_manifest_ci_secrets.template.json` to `.verification/ci_secrets_pilot.json` in the target repo.
2. Add lane input JSON under `.verification/ci_secrets/` (see `examples/ci_secrets/input_secrets_safe.json` for shape).
3. Install OVK in CI (advisory):

```yaml
env:
  OVK_PACKAGE_VERSION: "1.1.0"

- uses: fraware/open-verification-kernel@v1.1.0
  with:
    mode: advisory
    use-check: "true"
    changed-files: ${{ github.event.pull_request.diff_url }}  # or a checked-in diff artifact
```

4. Run for **2 weeks** on all agent PRs without blocking merges.

## Phase 1 — Measure

Track per PR:

| Metric | Target before strict |
|--------|----------------------|
| False positive rate | &lt; 5% |
| Time to first green after repair | &lt; 5 minutes |
| Block rate on known-bad fixtures | 100% |

Publish results in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md) under **External pilots**.

## Phase 2 — Strict on protected branch

When false positives stay below 5%:

```yaml
- uses: fraware/open-verification-kernel@v1.1.0
  with:
    mode: strict
    use-check: "true"
    emit-check: "true"
```

Require the OVK check on `main` / `release/*` only; keep advisory on experimental branches if needed.

## Phase 3 — Expand lanes

After ci_secrets is stable, add lanes one at a time using manifests from `examples/pilot_repos/`. Re-run advisory for each new lane before strict enforcement.

## Support artifacts

- Repair loop demo: [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md)
- Realistic diff corpus: `benchmarks/real_diffs/`
- External consumer workflow: `examples/github_workflows/external_consumer.yml`

## Reporting template

When publishing pilot metrics, include:

- Repository name (link)
- Lane(s) enabled
- Advisory duration (dates)
- PRs evaluated / blocked / false positives
- Median `ovk check` latency
- Strict mode enabled (yes/no)

Add entries to the **External pilots** section of [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
