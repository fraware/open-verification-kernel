# OVK Roadmap

## v0.1 delivered

OVK v0.1.0 ships:

- five MVP evidence lanes with CLI, examples, and benchmark coverage;
- unified release bundles with provenance and optional HMAC signing;
- evidence-quality gates in preflight;
- multi-lane verification manifests;
- diff-aware planning with workflow YAML reconstruction;
- hardened composite GitHub Action (single-lane and multi-lane);
- MCP stdio server for agent integrations.

Details: [STATUS.md](STATUS.md), [RELEASE.md](RELEASE.md).

## Hardening status (v1.0.0)

| Area | Status |
|---|---|
| Evidence honesty and quality gates | delivered |
| OPA + deterministic self-protection | delivered |
| Z3 authorization with deterministic fallback | delivered |
| Release bundles, provenance, HMAC + opt-in Sigstore | delivered |
| GitHub Action + CI dogfood (`use-check` default path) | delivered |
| FormalPR-Bench v1 (100 cases + extended categories) | delivered |
| Diff-aware workflow + IaC hunk parsing | delivered |
| MCP SDK transport (`ovk-mcp`, `pip install '.[mcp]'`) | delivered |
| Ten backend adapters (wave 1 + wave 2) | delivered |
| Pilot program (`ovk pilot`, five manifests) | delivered |

## Post-v1.0 priorities

1. PyPI publication and semver release automation.
2. Real-world OSS pilot repositories beyond example manifests.
3. Repository policy preferences and runtime budgets in backend routing.
4. External-repo Action validation at scale.
5. Deeper Z3 obligation expressiveness and counterexample minimization.
6. Community backend contributions and expanded template library (100+ intents).

## Historical phases (completed for v0.1 scope)

The 24-month full-vision roadmap (Phases 1–7) is complete at v1.0.0: `ovk check`, kernel orchestration, trust hardening, 10 backends, MCP agent loop, 50+ templates, FormalPR-Bench v1, and pilot program. Post-v1.0 work focuses on PyPI distribution, community backend contributions, and expanded real-world pilot metrics.

## One-year target

- Stable schemas and 10–15 backend adapters.
- 100 reusable property templates.
- Public benchmark for agentic PR verification.
- Enterprise and OSS pilot repositories.
