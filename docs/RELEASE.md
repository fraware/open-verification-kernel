# OVK Release

Maintainer guide for shipping Open Verification Kernel. Current readiness: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md). Full code and artifact assessment: [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md).

## Current release candidate

Package version: `1.2.0`.

Release judgment: **release candidate**. The five bounded evidence lanes, artifact chain, CLI, MCP surface, and composite Action are implemented. Backend routing remains advisory, external tagged-consumer validation remains pending, and the current source commit must pass all gates below before publication.

## Known limitations

- Generic backend routing does not yet control lane compilation or execution.
- Authorization, infrastructure, workflow, and deployment diff extraction remains conservative and heuristic.
- OPA and Z3 have native semantic paths; CBMC checks explicit or template harnesses; Cedar and six other external adapters do not yet perform native policy/proof execution.
- The 100-template catalog is broader than the production-executable property set.
- Auto-collected branch-protection metadata cannot reconstruct a removed required check without trusted before/after data.
- FormalPR-Bench is an internal curated regression suite, not an independent accuracy estimate.
- Current external-validation workflows use in-repository dogfooding; independent tagged consumers are still required.

## Source release gates

Run these gates on the exact non-`[skip ci]` source commit intended for release:

```bash
pip install -e '.[dev]'
pytest
ruff check ovk tests benchmarks scripts
python scripts/check_release_metadata.py
python scripts/validate_templates.py
python scripts/validate_capabilities.py
ovk release-preflight
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
ovk pilot
python scripts/external_smoke_checklist.py
```

Required evidence:

- [ ] core CI job is green on the source SHA;
- [ ] package job builds and installs the wheel outside the checkout;
- [ ] automatic-diff Action dogfood is green;
- [ ] strict known-bad Action dogfood produces `block` and the expected nonzero result;
- [ ] OPA, Z3, and CBMC native-execution checks are green;
- [ ] Cedar toolchain probe and deterministic-evidence honesty checks are green;
- [ ] full expanded benchmark and preflight artifacts are retained;
- [ ] complete release-bundle validation is green;
- [ ] current source SHA and workflow links are recorded in `CURRENT_RELEASE_STATUS.md`.

## Version and tag binding

The Publish workflow rejects a GitHub release whose tag does not equal `ovk.__version__` after removing an optional leading `v`.

Before tagging:

- [ ] `pyproject.toml`, `ovk.__version__`, and `ovk/core/release_metadata.py` agree;
- [ ] `SUPPORTED_COMMANDS` matches the Typer command surface;
- [ ] consumer examples reference the intended immutable release tag or commit;
- [ ] release notes describe actual backend execution semantics from [BACKENDS.md](BACKENDS.md);
- [ ] package classifier remains Beta until the production gate in the vision audit is met;
- [ ] benchmark and adoption summaries are regenerated from the release source.

Tag and create the release only after the source gates are attributable:

```bash
git tag -s v1.2.0 <VERIFIED_SOURCE_SHA>
git push origin v1.2.0
gh release create v1.2.0 \
  --verify-tag \
  --title "OVK v1.2.0" \
  --notes-file docs/RELEASE_NOTES_v1.2.0.md
```

## Package publication

The release-triggered Publish workflow:

1. verifies release-tag/package-version equality;
2. synchronizes package data;
3. runs tests, preflight, pilots, and the expanded benchmark;
4. builds and checks the sdist and wheel;
5. installs the wheel in an isolated environment outside the checkout;
6. validates packaged templates, capabilities, MCP discovery, and `ovk doctor`;
7. publishes to PyPI only after the protected `pypi` environment permits it.

PyPI configuration:

- prefer trusted publishing with an environment-bound OIDC policy;
- otherwise configure `PYPI_API_TOKEN` in the protected `pypi` environment;
- require maintainer review for the environment;
- retain the built distributions and verification artifacts.

## Attestation signing

### HMAC

Set `OVK_SIGNING_KEY` only in a controlled internal environment. Any consumer verifying the HMAC must possess the same secret. A signed envelope fails verification when the key is unavailable or different.

### Sigstore/cosign

Explicit Sigstore signing fails closed. The release workflow must supply:

```bash
export OVK_SIGSTORE_SIGNING=1
export OVK_COSIGN_IDENTITY='https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.0'
export OVK_COSIGN_ISSUER='https://token.actions.githubusercontent.com'
```

The exact identity must reflect the actual protected release workflow and tag policy. Verification binds the cosign bundle to both the expected certificate identity and OIDC issuer. Do not enable Sigstore signing until the release workflow has `id-token: write` and the identity policy has been tested end to end.

Required signing evidence:

- [ ] unsigned bundle validates;
- [ ] HMAC-signed bundle validates with the correct key and fails with the wrong or missing key;
- [ ] Sigstore-signed bundle validates with the trusted identity and issuer;
- [ ] tampered evidence, manifest, statement, and envelope each fail validation;
- [ ] signature and transparency artifacts are retained with the release.

## Independent consumer gate

Before describing v1.2.0 as production-stable:

- [ ] create a separate fixture repository;
- [ ] invoke `fraware/open-verification-kernel@v1.2.0`, never `uses: ./`;
- [ ] test advisory allow, advisory block, strict block, unknown/review, comment, and check-run paths;
- [ ] test a fork pull request with reduced token permissions;
- [ ] install the published wheel independently;
- [ ] complete at least two adjudicated advisory pilots according to [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md).

## External consumer example

```yaml
name: OVK
on:
  pull_request:

permissions:
  contents: read
  checks: write
  pull-requests: write

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2
      - uses: fraware/open-verification-kernel@v1.2.0
        with:
          mode: advisory
          use-check: "true"
          emit-check: "true"
          post-comment: "true"
```

When `changed-files` is omitted, the Action materializes the pull-request diff automatically. Start advisory, adjudicate results, then enable strict mode only for calibrated lanes with trusted inputs.

## Release history

| Version | Changelog |
|---|---|
| v1.2.0 | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

Upgrade paths: [MIGRATION.md](MIGRATION.md).
