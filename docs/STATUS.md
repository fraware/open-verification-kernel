# OVK Status

Current package version: **v1.2.1** (see `pyproject.toml` / `ovk.core.release_metadata.OVK_VERSION`). Working-tree adoption tracking may describe a future `v1.3.0-rc.1` candidate in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md); that does not change the installed package version until an rc cut.

## Summary

OVK is a solver-agnostic verification layer for AI-agent pull requests. It turns a PR diff into structured evidence: what was checked, what passed, what failed, and what still needs a human.

v1.2 improved adoption tooling (release status dashboard, example workflows, quality checks on all five check types). v1.1 added a realistic diff benchmark and required native checker CI for OPA, Z3, CBMC, and Cedar. Opt-in verifier-assurance (`ovk verifier …`) is documented under [assurance/GUIDE.md](assurance/GUIDE.md).

Changelog: [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md) (and [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) for the 1.2.0 baseline).

## Package

- Version `1.2.1` — install with `pip install -e '.[dev]'` from a checkout.
- Optional groups: `dev`, `solvers`, `mcp`, `assurance` (git/path pin `fb588a41a7eab68064429e3c4dfb26c328b9863d` until PyPI; see [PCS_PIN.md](PCS_PIN.md)).
- Primary command: `ovk check --changed-files <diff>`.
- Opt-in assurance CLI: `ovk verifier …` (requires resolved pcs-core pin; does not change ordinary CI).
- GitHub Action pin: `@v1.2.1` with optional `OVK_PACKAGE_VERSION=1.2.1` for PyPI installs.

## Check types

| # | What it guards | How to run on a PR |
|---|---|---|
| 1 | Agents cannot weaken their own CI gates | `ovk check` or `ovk ci` |
| 2 | Admin routes stay protected | `ovk check` |
| 3 | Sensitive infra is not exposed publicly | `ovk check` |
| 4 | Secrets are not used in untrusted CI contexts | `ovk check` |
| 5 | Deployments cannot skip approval steps | `ovk check` |

Details per check type: [LANES.md](LANES.md).

Backends (10 formal tools): [BACKENDS.md](BACKENDS.md). OPA, Z3, CBMC, and Cedar run as required checks in CI when installed.

## Key commands

| Command | Purpose |
|---|---|
| `ovk check` | Analyze a diff and run all affected checks |
| `ovk run` | Run a pre-built verification plan |
| `ovk doctor` | Validate local install and repo layout |
| `ovk bench` | Run the FormalPR-Bench regression suite |
| `ovk generate-test` | Turn a counterexample into a regression test |
| `ovk repair-suggest` | Suggest fix classes from evidence |
| `ovk template list/show/apply` | Browse and apply property templates |
| `ovk release-preflight` | Run release readiness checks |
| `ovk verifier …` | Opt-in assurance: describe, snapshot-config, run, replay, mutate, validate-evidence |
| `ovk-mcp` | MCP server for agent integrations |

## Quick commands

```bash
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
ovk release-preflight
python scripts/validate_templates.py
```

## Trust

- Optional HMAC signing via `OVK_SIGNING_KEY`.
- Optional Sigstore signing via `OVK_SIGSTORE_SIGNING=1`.
- Evidence quality checks reject inconsistent bundles (for example, an `allow` recommendation when a check actually failed).

## Benchmark

FormalPR-Bench scores correctness, routing, repair hints, and realistic PR diffs. Details: [BENCHMARK.md](BENCHMARK.md).

## Pilots and rollout

- In-repo examples: [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
- External repos: [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md).

## Verifier-assurance (opt-in)

Reproducible verifier execution with PCS-bound profiles and evidence packs. Separate from ordinary PR checks. Guide: [assurance/GUIDE.md](assurance/GUIDE.md). Architecture: [adr/0001-verifier-assurance-architecture.md](adr/0001-verifier-assurance-architecture.md). Pinned to pcs-core `fb588a41a7eab68064429e3c4dfb26c328b9863d` (git SHA install; PyPI pending). See [PCS_PIN.md](PCS_PIN.md).

## Known limitations

See [RELEASE.md](RELEASE.md#known-limitations). Experimental / non-strict compiler paths: [EXPERIMENTAL_PATHS.md](EXPERIMENTAL_PATHS.md). Adoption readiness: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Upgrading

- **v1.2.0 → v1.2.1:** [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md) and [MIGRATION.md](MIGRATION.md)
- **v1.1.0 → v1.2.0:** [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) and [MIGRATION.md](MIGRATION.md#upgrade-from-v110-to-v120)
- **Older versions:** [MIGRATION.md](MIGRATION.md)
