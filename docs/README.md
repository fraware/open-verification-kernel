# OVK Documentation

Documentation for Open Verification Kernel **v1.2.0**.

Use this index as the canonical entry point. Each guide covers one topic; cross-links replace duplicated content across files.

## By role

| Role | Start here |
|---|---|
| **Adopting in CI** | [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) → [INTEGRATION.md](INTEGRATION.md) → [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) |
| **Contributing code** | [CONTRIBUTING.md](CONTRIBUTING.md) → [ARCHITECTURE.md](ARCHITECTURE.md) → [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md) |
| **Maintainers** | [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) → [RELEASE.md](RELEASE.md) → `ovk release-preflight` (release readiness checks) |
| **Spec / security review** | [SYSTEM_SPEC.md](SYSTEM_SPEC.md) → [FORMAL_SPEC.md](FORMAL_SPEC.md) → [THREAT_MODEL.md](THREAT_MODEL.md) |

## Start here

| Document | Purpose |
|---|---|
| [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) | Adoption dashboard — can I pin strict mode today? |
| [STATUS.md](STATUS.md) | Capabilities, CLI surface, and trust model |
| [INTEGRATION.md](INTEGRATION.md) | Install locally or in GitHub Actions |
| [RELEASE.md](RELEASE.md) | Maintainer release guide and known limitations |
| [MIGRATION.md](MIGRATION.md) | Upgrade paths between versions |

## Operations

| Document | Purpose |
|---|---|
| [BENCHMARK.md](BENCHMARK.md) | FormalPR-Bench categories, real-diff corpus, leaderboard artifacts |
| [BACKENDS.md](BACKENDS.md) | Backend requirements in CI, install matrix, fallback semantics |
| [POLICY.md](POLICY.md) | Verification routing configuration for `.verification/config.yml` |
| [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md) | Weekly external validation matrix |
| [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) | Advisory→strict rollout on external OSS repos |
| [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md) | In-repo pilot metrics and external pilot reporting |
| [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md) | Counterexample-to-repair workflow for MCP agents |
| [benchmarks/adoption-summary.json](benchmarks/adoption-summary.json) | Machine-readable adoption metrics (see [BENCHMARK.md](BENCHMARK.md) for field-name notes) |

## Design and specification

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture and runner flows |
| [SYSTEM_SPEC.md](SYSTEM_SPEC.md) | System specification |
| [FORMAL_SPEC.md](FORMAL_SPEC.md) | Formal properties and security rules |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model |
| [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md) | Backend adapter contract |
| [ROADMAP.md](ROADMAP.md) | Release history and planned work |

## Reference

| Document | Purpose |
|---|---|
| [LANES.md](LANES.md) | Check types, inputs, and semantics |
| [ARTIFACTS.md](ARTIFACTS.md) | Release bundle layout and artifact formats |
| [SCHEMA_INDEX.md](SCHEMA_INDEX.md) | JSON schema index |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guide |

## Release history

| Document | Purpose |
|---|---|
| [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) | v1.2.0 changelog |
| [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) | v1.1.0 changelog |
| [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) | v1.0.0 changelog |

## Folder layout

```text
docs/
  README.md                 # this index
  CURRENT_RELEASE_STATUS.md # living adoption dashboard
  STATUS.md                 # stable capability inventory
  RELEASE.md                # maintainer guide + known limitations
  RELEASE_NOTES_v*.md       # immutable per-version changelogs
  INTEGRATION.md            # install and GitHub Actions
  LANES.md, BACKENDS.md, …  # reference and operations guides
  ARCHITECTURE.md, …        # design and specification
  benchmarks/               # committed leaderboard and adoption JSON
  templates/                # external pilot manifest template
```
