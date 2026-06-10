# OVK v1.1.0 Release

Release notes and maintainer checklists for Open Verification Kernel v1.1.0.

## Release notes

OVK v1.1 is the depth-first release after v1.0 ecosystem hardening. It ships technical improvements for real PR verification and external adoption readiness:

- **Tier-1 native CI** — blocking OPA, Z3, and CBMC jobs in `native-backends-tier1.yml` with pinned install scripts and evidence honesty checks
- **Real diff corpus** — 16 sanitized unified diffs in `benchmarks/real_diffs/` covering secrets, auth, infra, deployment, and multi-surface patterns
- **FormalPR-Bench depth** — `real_diff` leaderboard category, repair-loop cases for ci_secrets/auth/infra/deployment lanes
- **PyPI-pinned Action** — set `OVK_PACKAGE_VERSION=1.1.0` to install `open-verification-kernel==1.1.0` from PyPI; defaults to `pip install .` for local development
- **External pilot kit** — [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md), `external_oss_ci_secrets.json` manifest template, advisory→strict rollout guidance

See [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) for the full changelog.

### Known limitations

- IaC and auth diff compilation remains conservative; partial hunks may yield `require_human_review`.
- Tier-2 native backends (Cedar, TLA+, Kani, Dafny, Verus, Lean, Alloy) remain informational in CI.
- External OSS pilot metrics are template-only until community repos complete advisory runs.

## Readiness checklist

All items satisfied for v1.1.0:

- [x] `ovk check` on multi-surface and real_diff fixtures in &lt;45s
- [x] 10 capability manifests; 100 templates validated against JSON schema
- [x] FormalPR-Bench canonical + extended + real_diff cases green
- [x] Release preflight: metadata, command surface, smoke, quality, adversarial, multi-lane, latency, bench, templates, external validation
- [x] GitHub Action supports PyPI install via `OVK_PACKAGE_VERSION`
- [x] External consumer example pins `@v1.1.0`
- [x] External pilot playbook and case-study metrics template published

## Tagging checklist

Before tagging `v1.1.0`:

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

- [x] Package version matches `ovk/core/release_metadata.py` (`1.1.0`).
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
- [x] `release-preflight` passes (includes `pilot_program` and `external_validation_matrix`).
- [x] `ovk bench` and `ovk pilot` pass.

### Artifacts

- [x] Invalid input never produces `allow`.
- [x] Release bundles pass `ovk validate-outputs`.
- [x] HMAC and optional Sigstore signing verified in CI.

## PyPI publication

1. Create a GitHub release for tag `v1.1.0`.
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

## GitHub release (maintainer)

After pushing tag 1.1.0 to origin:

`ash
gh release create v1.1.0 --title "OVK v1.1.0" --notes-file docs/RELEASE_NOTES_v1.1.0.md
`

Publishing the release triggers the Publish workflow (PyPI upload). If gh is not authenticated on your machine:

`ash
gh auth login
git push origin main
git push origin v1.1.0
gh release create v1.1.0 --title "OVK v1.1.0" --notes-file docs/RELEASE_NOTES_v1.1.0.md
`

Verify the release at https://github.com/fraware/open-verification-kernel/releases/tag/v1.1.0.

## External consumer pin

Fork consumers should use:

```yaml
env:
  OVK_PACKAGE_VERSION: "1.1.0"
jobs:
  ovk:
    steps:
      - uses: fraware/open-verification-kernel@v1.1.0
        with:
          mode: advisory
          use-check: "true"
```

See `examples/github_workflows/external_consumer.yml`.
