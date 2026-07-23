# OVK Release

Maintainer guide for shipping Open Verification Kernel. Current readiness: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md). Full code and artifact assessment: [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md).

## Current release candidate

Package version: `1.2.1`.

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
git tag -s v1.2.1 <VERIFIED_SOURCE_SHA>
git push origin v1.2.1
gh release create v1.2.1 \
  --verify-tag \
  --title "OVK v1.2.1" \
  --notes-file docs/RELEASE_NOTES_v1.2.1.md
```

Note: `v1.2.0` already exists as an immutable tag on an earlier commit without the protected Publish Sigstore path. Do not move that tag.

## Package publication

The release-triggered Publish workflow (`.github/workflows/publish.yml`):

1. verifies release-tag/package-version equality;
2. synchronizes package data;
3. runs tests, preflight, pilots, and the expanded benchmark;
4. builds and checks the sdist and wheel;
5. installs the wheel in an isolated environment outside the checkout;
6. validates packaged templates, capabilities, MCP discovery, and `ovk doctor`;
7. keyless-signs distributions with cosign in the protected `sigstore` environment (`id-token: write`);
8. verifies signatures in the same workflow against the exact identity + OIDC issuer, runs a tamper test, and retains cosign bundles;
9. publishes to PyPI only after the protected `pypi` environment permits it (skipped on `workflow_dispatch` dry-run).

PyPI configuration:

- prefer trusted publishing with an environment-bound OIDC policy;
- otherwise configure `PYPI_API_TOKEN` in the protected `pypi` environment;
- require maintainer review for the environment;
- retain the built distributions and verification artifacts.

### Sigstore dry-run (no PyPI publish)

After this workflow is on `main`:

```bash
gh workflow run Publish.yml --ref main -f dry_run=true
gh run watch
```

`workflow_dispatch` never publishes to PyPI and skips the full release-gate suite so keyless signing can be exercised while unrelated CI failures exist on `main`. It still builds the sdist/wheel, signs with cosign, verifies, tampers, and retains bundles. Dry-run signatures are bound to `@refs/heads/main` (or the dispatched branch). They are **not** a production pin. Production consumers must verify against an immutable tag identity (below). Full release events still run the complete verify suite before signing and PyPI publish.

## Attestation signing

### HMAC

Set `OVK_SIGNING_KEY` only in a controlled internal environment. Any consumer verifying the HMAC must possess the same secret. A signed envelope fails verification when the key is unavailable or different.

### Sigstore/cosign (keyless)

Explicit Sigstore signing fails closed. The protected Publish `sigstore` job has `id-token: write` and signs with `cosign sign-blob` (no long-lived keys in git or secrets).

**Exact OIDC issuer (GitHub Actions):**

```text
https://token.actions.githubusercontent.com
```

**Exact workflow identity (production / immutable tag):**

```text
https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/vX.Y.Z
```

Example for v1.2.1:

```bash
export OVK_SIGSTORE_SIGNING=1
export OVK_COSIGN_IDENTITY='https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.1'
export OVK_COSIGN_ISSUER='https://token.actions.githubusercontent.com'
```

Consumer verification of a retained bundle:

```bash
cosign verify-blob \
  --bundle path/to/artifact.cosign.bundle.json \
  --certificate-identity "https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  path/to/artifact.whl
```

Policy:

- Trust only the Publish workflow path above; do not accept arbitrary workflows in this repository.
- Trust only immutable `refs/tags/v*` identities for production artifacts.
- The `sigstore` GitHub Environment should require maintainer reviewers (same class of protection as `pypi`).
- Cosign bundles and `ovk-sigstore-summary.json` are retained as workflow artifacts (90 days) and attached to the GitHub Release on `release` events.
- Same-workflow steps: sign → verify with exact identity/issuer → mutate a copy and expect verify failure (`scripts/sigstore_release.py`).

Required signing evidence:

- [x] unsigned bundle validates;
- [x] HMAC-signed bundle validates with the correct key and fails with the wrong or missing key;
- [x] Sigstore-signed bundle validates with the trusted identity and issuer on a **protected** `workflow_dispatch` dry-run ([run 30008891551](https://github.com/fraware/open-verification-kernel/actions/runs/30008891551); identity `@refs/heads/main`, environment `sigstore` with required reviewers, retained `ovk-sigstore-bundles`);
- [x] tampered evidence, manifest, statement, and envelope each fail validation (unit / release verifier); same-workflow artifact tamper test exercised in the dry-run above;
- [x] signature and transparency artifacts retained as workflow artifacts on the dry-run above;
- [ ] **Not complete until immutable-tag protected release E2E:** a GitHub **Release** event on an immutable `refs/tags/v*` (full `verify` job green + keyless cosign + release-attached bundles) has succeeded end to end. Branch dry-runs do not alone close the production pin. Do not claim production signing complete until that box is checked.

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
      - uses: fraware/open-verification-kernel@v1.2.1
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
| v1.2.1 | [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md) |
| v1.2.0 | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

Upgrade paths: [MIGRATION.md](MIGRATION.md).
