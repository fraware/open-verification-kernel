# OVK Release

Maintainer guide for shipping Open Verification Kernel. For adoption readiness see [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md). For consumer changelogs see [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) and older notes in [Release history](#release-history).

## Current release: v1.2.0

v1.2.0 improves adoption tooling: quality checks on all five check types, clearer GitHub Action outputs, and example rollout workflows.

Changelog: [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md).

## Known limitations

- IaC and auth diff compilation remains conservative; partial hunks may yield `require_human_review`.
- Optional native checkers (TLA+, Kani, Dafny, Verus, Lean, Alloy) remain informational in CI.
- External OSS pilot metrics are template-only until community repos complete advisory runs.
- Auto-collected branch-protection metadata sets identical before/after required checks; detecting check **removal** requires explicit `check-metadata` with before/after JSON.
- PyPI wheel is not live until a maintainer creates the GitHub release and Publish workflow runs.

## Maintainer: tag v1.2.0

```bash
pip install -e '.[dev]'
pytest
ruff check ovk tests benchmarks scripts
python scripts/check_release_metadata.py
python scripts/validate_templates.py
ovk release-preflight
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
python scripts/external_smoke_checklist.py
```

Before tagging:

- [ ] Package version matches `ovk/core/release_metadata.py` (`1.2.0`).
- [ ] `SUPPORTED_COMMANDS` matches `ovk/cli.py`.
- [ ] Consumer examples pin `@v1.2.0` and `OVK_PACKAGE_VERSION: "1.2.0"`.
- [ ] [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) reflects shipped state.
- [ ] `docs/benchmarks/adoption-summary.json` refreshed: `python scripts/render_pilot_metrics.py`.

```bash
git push origin main
git push origin v1.2.0
gh release create v1.2.0 --title "OVK v1.2.0" --notes-file docs/RELEASE_NOTES_v1.2.0.md
```

Verify: https://github.com/fraware/open-verification-kernel/releases/tag/v1.2.0

## Maintainer: PyPI publication

**Status:** workflow and package metadata are ready; the wheel is not on PyPI until a maintainer creates the GitHub release below.

1. Create a GitHub release for tag `v1.2.0`.
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

## Maintainer: repository health

### Package

- [x] `pip install -e '.[dev]'` succeeds.
- [x] Console scripts `ovk` and `ovk-mcp` registered.
- [x] `python -m build` and `twine check dist/*` pass in CI `package` job.

### Tests and release readiness

- [x] `pytest` passes (374 passed, 12 skipped).
- [x] `ruff check` passes.
- [x] `release-preflight` passes (12 required checks + optional pilot metrics dry-run).
- [x] `ovk bench --expanded` and `ovk pilot` pass.
- [x] External validation matrix exercises Action scenarios weekly.

### Artifacts

- [x] Invalid input never produces `allow`.
- [x] Release bundles pass `ovk validate-outputs`.
- [x] HMAC and optional Sigstore signing verified in CI.

## External consumer pin

```yaml
env:
  OVK_PACKAGE_VERSION: "1.2.0"
jobs:
  ovk:
    permissions:
      contents: read
      checks: write
      pull-requests: write
    steps:
      - uses: fraware/open-verification-kernel@v1.2.0
        with:
          mode: advisory
          use-check: "true"
          emit-check: "true"
```

Example rollout workflows: `examples/github_workflows/`. Integration guide: [INTEGRATION.md](INTEGRATION.md).

## Release history

| Version | Changelog |
|---|---|
| v1.2.0 | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

Upgrade paths: [MIGRATION.md](MIGRATION.md).
