# OVK v1.0.0 Release

Release notes and maintainer checklists for Open Verification Kernel v1.0.0.

## Release notes

OVK v1.0 is the first production-ready release of the full 24-month vision baseline:

- **Autonomous PR verification** via `ovk check` on unified diffs
- **10 backends** with deterministic fallbacks (Cedar, TLA+, Kani, Dafny, Verus, Lean, CBMC, Alloy, OPA, Z3)
- **Kernel orchestration** with context builder, risk ranker, budget-aware router, obligation compiler
- **Agent loop** via MCP SDK tools, repair hints, regression artifact generation, repo memory
- **FormalPR-Bench v1** with multi-dimensional leaderboard JSON
- **50+ intent templates** with schema validation CI
- **Second OPA domain pack** for infrastructure exposure Rego policies
- **Pilot program** manifests and case studies

### Known limitations

- IaC and auth diff compilation is conservative; partial hunks may yield `require_human_review`.
- Native backend binaries remain optional; deterministic oracles are used in CI without them.
- PyPI publication is automated via `.github/workflows/publish.yml` on GitHub release (requires `PYPI_API_TOKEN` and `pypi` environment).

## Readiness checklist

All items satisfied for v1.0.0:

- [x] `ovk check` on multi-surface diffs in &lt;45s (typically &lt;200ms locally)
- [x] 10 capability manifests; 50+ templates validated against JSON schema
- [x] FormalPR-Bench canonical + extended cases green; 100-case expanded set green
- [x] Release preflight: metadata, command surface, smoke, quality, adversarial, multi-lane, latency, bench, templates
- [x] GitHub Action dogfooded with `use-check: true` default
- [x] Migration guide and pilot case studies published

## Tagging checklist

Before tagging `v1.0.0`:

```bash
pip install -e '.[dev]'
pytest
ruff check ovk tests benchmarks scripts
python scripts/check_release_metadata.py
python scripts/validate_templates.py
ovk release-preflight
ovk bench --expanded
```

Confirm:

- [x] Package version matches `ovk/core/release_metadata.py` (`1.0.0`).
- [x] `SUPPORTED_COMMANDS` matches `ovk/cli.py`.
- [x] Documentation in `docs/STATUS.md`, `docs/INTEGRATION.md`, `docs/MIGRATION.md` is current.

## Repository health checklist

### Package

- [x] `pip install -e '.[dev]'` succeeds.
- [x] Console scripts `ovk` and `ovk-mcp` registered.
- [x] `python -m build` and `twine check dist/*` pass in CI `package` job.

### Tests and release gates

- [x] `pytest` passes.
- [x] `ruff check` passes.
- [x] `release-preflight` passes (includes `pilot_program`).
- [x] `ovk bench` and `ovk pilot` pass.

### Artifacts

- [x] Invalid input never produces `allow`.
- [x] Release bundles pass `ovk validate-outputs`.
- [x] HMAC and optional Sigstore signing verified in CI.

## PyPI publication

1. Create a GitHub release for tag `v1.0.0`.
2. Ensure repository secrets: `PYPI_API_TOKEN` (PyPI trusted publishing or API token).
3. Configure GitHub Environment `pypi` with required reviewers if desired.
4. The `Publish` workflow runs release gates, builds the wheel/sdist, and uploads to PyPI.

Local dry run:

```bash
python -m pip install build twine
python scripts/sync_package_data.py
python -m build
twine check dist/*
```
