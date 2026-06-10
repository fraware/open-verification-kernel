# Contributing to OVK

OVK is an open interoperability layer. Contributions should make formal methods tools easier to use in AI-agent engineering workflows.

## Contribution priorities

1. Schemas and validation logic
2. Adapter manifests and implementations
3. Property templates with clear engineering value
4. End-to-end PR evidence examples
5. Tests that prevent evidence dishonesty
6. Benchmark fixtures for agent-authored PR verification

## Design rules

- Do not add a backend without a capability manifest.
- Do not return a bare boolean from an adapter.
- Do not collapse `unknown`, `error`, or `skipped` into `pass`.
- Do not claim generic verification without assumptions and limits.
- Prefer narrow, useful property templates over broad unverifiable claims.
- Keep the kernel backend-neutral and guarantee-aware.

## Start here

1. Read [ARCHITECTURE.md](ARCHITECTURE.md) and [STATUS.md](STATUS.md).
2. Run the release gate:

```bash
pip install -e '.[dev]'
pytest
python scripts/release_preflight.py
```

## Key code paths

| Area | Location |
|---|---|
| CLI | `ovk/cli.py` |
| Lane evaluation | `ovk/core/multi_lane.py` |
| Release bundles | `ovk/core/release_bundle.py` |
| Evidence quality | `ovk/core/evidence_quality.py` |
| Planning | `ovk/core/planner.py`, `ovk/core/change_detection.py` |
| Diff parsing | `ovk/core/diff_parser.py`, `ovk/adapters/workflow/` |
| Adapters | `ovk/adapters/{opa,z3,infra,ci_secrets,deployment}/` |
| MCP | `ovk/mcp_server.py`, `ovk/mcp_stdio.py` |
| GitHub Action | `action.yml` |
| Schemas | `schemas/` |
| Examples | `examples/` |
| Benchmark | `benchmarks/formal_pr_bench/` |

## Adding a new lane

1. Define input schema in `schemas/`.
2. Implement adapter under `ovk/adapters/`.
3. Register in `ovk/core/multi_lane.py` (`evaluate_lane`, `LANE_ALIASES`).
4. Add CLI command in `ovk/cli.py`.
5. Add examples, regression fixture, and benchmark case.
6. Update `ovk/core/release_metadata.py` and [SCHEMA_INDEX.md](SCHEMA_INDEX.md).
7. Document in [LANES.md](LANES.md).
8. Add to `examples/verification_manifests/full_mvp.json` if MVP-scope.

## Local setup

```bash
pip install -e '.[dev]'
pytest
ruff check ovk tests benchmarks scripts
python scripts/release_preflight.py
```

## Adding an adapter

An adapter must include:

- `capability.json` (or manifest under `adapters/`)
- implementation code under `ovk/adapters/`
- tests and at least one fixture
- documentation of assumptions and limits
- normalized result mapping per [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md)

## Adding a template

A template must include:

- verification intent JSON under `templates/`
- threat or engineering scenario
- expected backend class
- failure modes and anti-vacuity considerations
- example evidence fixture when possible

## Conventions

- Invalid input must not produce `allow`.
- Unknown and error states require human review.
- Use shared output helpers in `ovk/core/run_outputs.py`.
- Release artifacts must pass `ovk validate-outputs`.
- Update [STATUS.md](STATUS.md) when the command surface changes.
- Run `python scripts/check_command_surface.py` after CLI changes.

## Release documentation

Before tagging, complete [RELEASE.md](RELEASE.md) checklists.
