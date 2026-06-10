# OVK Roadmap

Current release: **v1.1.0**. Capability snapshot: [STATUS.md](STATUS.md).

## v1.1.0 delivered

| Area | Status |
|---|---|
| Tier-1 native CI (OPA, Z3, CBMC, Cedar blocking jobs) | delivered |
| Real diff corpus (`benchmarks/real_diffs/`, 16 cases) | delivered |
| FormalPR-Bench `real_diff` category and repair-loop depth | delivered |
| PyPI-pinned GitHub Action (`OVK_PACKAGE_VERSION=1.1.0`) | delivered |
| External pilot playbook, OSS manifest template, adoption metrics | delivered |

Changelog: [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md).

## v1.0.0 baseline (delivered)

| Area | Status |
|---|---|
| Five MVP evidence lanes with CLI, examples, and benchmark coverage | delivered |
| Unified release bundles with provenance and optional HMAC signing | delivered |
| Evidence-quality gates in preflight | delivered |
| Multi-lane verification manifests | delivered |
| Diff-aware planning with workflow YAML reconstruction | delivered |
| Hardened composite GitHub Action (`use-check` default path) | delivered |
| MCP SDK transport (`ovk-mcp`, `pip install '.[mcp]'`) | delivered |
| Ten backend adapters (wave 1 + wave 2) | delivered |
| Pilot program (`ovk pilot`, five manifests) | delivered |
| FormalPR-Bench v1 (100 cases + extended categories) | delivered |

Changelog: [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md).

## Ecosystem hardening (v1.0.x, delivered)

| Area | Status |
|---|---|
| Evidence honesty and quality gates | delivered |
| OPA + deterministic self-protection | delivered |
| Z3 authorization with deterministic fallback | delivered |
| Release bundles, provenance, HMAC + opt-in Sigstore | delivered |
| GitHub Action + CI dogfood | delivered |
| Diff-aware workflow + IaC hunk parsing | delivered |
| FormalPR-Bench shields.io badge (committed JSON on `main`) | delivered |
| Template library expanded to 100 schema-valid intents | delivered |
| Weekly external validation matrix workflow | delivered |
| Native backend CI matrix (10 backends, tier-2 informational) | delivered |
| Router policy schema, recipes ([POLICY.md](POLICY.md)), `ovk doctor` config validation | delivered |
| PyPI publish workflow and semver release automation | ready (publication pending GitHub release + `PYPI_API_TOKEN`) |

## Future priorities

1. Real-world OSS pilot repositories with published metrics in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
2. Deeper Z3 obligation expressiveness and counterexample minimization.
3. Community backend contributions beyond the native install matrix.
4. Full native CBMC harness execution (today: contract probe + deterministic oracle).

## Historical note

The 24-month vision (Phases 1–7) shipped through v1.0.0: `ovk check`, kernel orchestration, trust hardening, 10 backends, MCP agent loop, 100 templates, FormalPR-Bench v1, and the pilot program. v1.1.0 added depth-first real-diff coverage, tier-1 native CI, and external adoption tooling.
