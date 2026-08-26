# OVK Release

Maintainer procedure for attributable Open Verification Kernel releases. Read this together with [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md), [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md), and [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md).

## Current release candidate

Package version: `1.3.0-rc.1`.

The corresponding candidate tag is `v1.3.0-rc.1`. A source commit is **not** release-authorized merely because PR CI is green. `verified_source_sha` is minted only by the live release-ledger authorizer after the exact candidate has candidate-bound workflow, holdout, consumer, and distribution provenance. Until that succeeds, the release ledger must remain `authorized=false`, `verified_source_sha=null`, `published=false`, and `tag=null`.

## Non-negotiable publication invariant

**Do not manually create or publish a GitHub Release before the Publish workflow.**

`.github/workflows/publish.yml` is an authorization-first state machine:

1. a signed annotated Git tag identifies one immutable source commit;
2. the seven required release-evidence workflows are rerun with `workflow_dispatch` on that tag;
3. Publish is dispatched on the **same tag ref**;
4. the exact wheel and sdist are built once;
5. the release ledger independently re-resolves exact GitHub run IDs, required holdout/consumer artifacts, and local distribution hashes;
6. only an authorized ledger may carry `verified_source_sha`;
7. the exact distributions and authorized ledger are keyless-signed and verified with Sigstore;
8. when `publish=true`, a GitHub Release is created or recovered as a **draft only** and receives the authorized artifacts;
9. PyPI Trusted Publishing occurs only for those exact authorized distribution bytes;
10. PyPI is independently re-read and required to expose exactly the authorized filenames and SHA-256 values;
11. only then is the already-staged GitHub Release made public.

A `release: published` event is intentionally **not** a production trigger. At that point a GitHub Release would already be public and authorization would be too late.

## 1. Freeze the candidate

Run source gates on the exact commit intended for the tag. Required local checks include:

```bash
pip install -e '.[dev]'
pytest
ruff check ovk tests benchmarks scripts
python scripts/check_release_metadata.py
python scripts/validate_templates.py
python scripts/validate_capabilities.py
python scripts/validate_adapter_conformance.py
python scripts/render_capability_tables.py --check
python scripts/render_tcb_doc.py --check
python scripts/verify_rc_dod.py
python scripts/verify_rc_install.py
ovk release-preflight
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
ovk pilot
python scripts/external_smoke_checklist.py
```

Before tagging, require the branch candidate itself to pass CI, Repro baseline, Native Backends Tier 1, and Native Backends Tier 1b. These development gates detect defects before the immutable tag is created. Release authorization later requires new tag-bound runs and does not reuse PR runs.

Version surfaces must agree exactly:

- `pyproject.toml` version;
- `ovk.core.release_metadata.OVK_RELEASE_CANDIDATE`;
- `ovk.__version__`;
- tag name `v<OVK_RELEASE_CANDIDATE>`.

For this RC, that is `1.3.0-rc.1` and `v1.3.0-rc.1`. PyPI normalizes the version to `1.3.0rc1`; the workflow computes that normalization with `packaging.version.Version` rather than by string rewriting.

## 2. Create a signed annotated immutable tag

Before creating or pushing the release tag, live-verify repository ref protection:

- `main` must be protected against force-push and deletion by branch protection or an active equivalent ruleset;
- the release-tag namespace (`v*`, or a stricter equivalent covering the RC and future release tags) must be protected against update and deletion after creation;
- these settings must be checked from live GitHub repository state, not inferred from this document.

For `v1.3.0-rc.1`, the current ref-protection closure is tracked in issue #25. Do not treat the existence of that issue as evidence that the settings are configured.

Create the tag only after the candidate commit is final and the ref-integrity precondition above is satisfied:

```bash
export CANDIDATE_SHA='<exact 40-hex candidate commit>'
export TAG='v1.3.0-rc.1'

git tag -s "$TAG" "$CANDIDATE_SHA"
git push origin "$TAG"
```

The production authorizer requires an **annotated** tag whose signature GitHub reports as verified and whose direct target is exactly `CANDIDATE_SHA`. Lightweight tags, unsigned annotated tags, indirect/wrong targets, moved historical tags, or tags whose version differs from package metadata fail closed.

Ref protection is additional integrity control, not a substitute for those cryptographic and exact-target checks. The release authorizer must independently resolve the annotated tag object and candidate target on every run.

Do not move `v1.2.1` or earlier historical tags. Do not re-attribute historical Sigstore evidence to the new candidate.

## 3. Produce tag-bound release evidence

All seven required workflows must be `workflow_dispatch` runs on `--ref "$TAG"`. This is deliberate: PR runs are development evidence, not final release evidence. CI, Repro, Tier 1, and Tier 1b explicitly checkout `${{ github.event.pull_request.head.sha || github.sha }}` so the bytes executed equal the run's recorded head rather than GitHub's synthetic PR merge ref.

### 3.1 Core validation matrix

Dispatch these four workflows on the tag:

```bash
gh workflow run ci.yml --ref "$TAG"
gh workflow run repro-baseline.yml --ref "$TAG"
gh workflow run native-backends-tier1.yml --ref "$TAG"
gh workflow run native-backends-tier1b.yml --ref "$TAG"
```

Require each run to complete successfully. Repro baseline must retain all six Linux/macOS/Windows × Python 3.10/3.12 cells; the native tiers must not silently skip required backends.

### 3.2 Label-free holdout prediction

Run the prediction workflow on the tag. It has no holdout labels and no holdout download token:

```bash
gh workflow run holdout-predict.yml --ref "$TAG"
```

After it completes, record its exact GitHub Actions run ID:

```bash
export PREDICT_RUN_ID="$(
  gh run list \
    --workflow holdout-predict.yml \
    --commit "$CANDIDATE_SHA" \
    --event workflow_dispatch \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId'
)"
test -n "$PREDICT_RUN_ID"
```

The prediction artifact contains both `holdout-predictions.json` and `holdout-prediction-manifest.json`. The manifest binds the exact prediction-file SHA-256 and candidate SHA.

### 3.3 Label-separated holdout evaluation

The evaluation workflow must consume the prediction artifact from that **exact** prior run ID. It independently checks candidate identity and the prediction-file digest before consulting the frozen labeled holdout.

```bash
export HOLDOUT_TAG='v0.1.0-synthetic'          # replace only through governed holdout versioning
export HOLDOUT_ASSET_SHA256='<frozen 64-hex release-asset digest>'

gh workflow run holdout-eval.yml \
  --ref "$TAG" \
  -f holdout_tag="$HOLDOUT_TAG" \
  -f asset_sha256="$HOLDOUT_ASSET_SHA256" \
  -f predictions_artifact='formalpr-holdout-predictions' \
  -f predictions_run_id="$PREDICT_RUN_ID" \
  -f candidate_source_sha="$CANDIDATE_SHA"
```

The resulting public aggregate must cryptographically bind:

```text
candidate SHA
  -> exact label-free predictions SHA-256
  -> exact frozen holdout release-asset SHA-256
  -> exact aggregate artifact SHA-256
```

Ordinary holdout prediction/evaluation artifacts must never mint `verified_source_sha`.

### 3.4 Independent consumer pins

Run the consumer verifier on the same tag and require both independent consumer repositories to pin the exact 40-hex OVK candidate:

```bash
gh workflow run consumer-pin-verification.yml \
  --ref "$TAG" \
  -f ovk_candidate_sha="$CANDIDATE_SHA" \
  -f fastapi_ref=main \
  -f express_ref=main
```

The retained evidence records each consumer repository, requested ref, exact consumer checkout SHA, exact OVK pin, and SHA-256 digests of the consumer workflow files. `uses: ./` is forbidden as consumer evidence.

## 4. Confirm the complete release-evidence set

Before Publish, there must be one successful tag-bound `workflow_dispatch` run for each required workflow:

- `CI`;
- `Repro baseline`;
- `Native Backends Tier 1`;
- `Native Backends Tier 1b`;
- `FormalPR-Holdout predict`;
- `FormalPR-Holdout eval`;
- `Consumer Pin Verification`.

The Publish authorizer independently checks this again. `scripts/collect_workflow_evidence.py --required-event workflow_dispatch` only drafts observations; it cannot authorize. `scripts/verify_release_ledger_github.py` re-fetches every exact run ID via the GitHub API, requires the run event to be `workflow_dispatch`, checks candidate/repository/workflow identity and success, downloads exact holdout and consumer artifacts, verifies their internal bindings, hashes the local wheel and sdist, and only then may mint `verified_source_sha`.

## 5. Authorization and Sigstore dry run

A dry run still requires a real signed tag and the complete release-evidence set. It performs the full authorization/build/Sigstore path but does not create a GitHub Release or publish to PyPI:

```bash
gh workflow run publish.yml \
  --ref "$TAG" \
  -f tag="$TAG" \
  -f publish=false
```

The workflow rejects branch-bound dispatches even if the job later checks out a tag. Both `GITHUB_REF` and the Sigstore `GITHUB_WORKFLOW_REF` must be bound to `refs/tags/$TAG`.

The production Sigstore identity is therefore exactly:

```text
https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/vX.Y.Z
```

and the exact GitHub Actions OIDC issuer is:

```text
https://token.actions.githubusercontent.com
```

The `sigstore` job signs and immediately verifies the wheel, sdist, and authorized release ledger, then mutates copies and requires verification to fail. Retained cosign bundles are part of the signed release transaction.

## 6. Publish

Once the authorization/Sigstore path is satisfactory, dispatch the same workflow on the same immutable tag with publication enabled:

```bash
gh workflow run publish.yml \
  --ref "$TAG" \
  -f tag="$TAG" \
  -f publish=true
```

Do **not** run `gh release create` beforehand. Publish owns the GitHub Release lifecycle.

The publication path is:

```text
AUTHORIZED LEDGER
      |
      v
SIGSTORE SIGN + VERIFY + TAMPER TEST
      |
      v
PRIVATE GITHUB RELEASE DRAFT + AUTHORIZED ASSETS
      |
      v
PYPI TRUSTED PUBLISHING
      |
      v
READ PYPI BACK; REQUIRE EXACT FILENAMES + SHA-256
      |
      v
PATCH THE EXISTING DRAFT TO draft=false
```

The draft contains the exact wheel/sdist, `release-ledger.authorized.json`, and retained Sigstore bundle JSON. It remains non-public throughout PyPI publication.

## 7. PyPI trust and recovery semantics

PyPI publication uses `pypa/gh-action-pypi-publish` with GitHub OIDC Trusted Publishing in the protected `pypi` environment. Long-lived `PYPI_API_TOKEN`/password authentication is intentionally not part of the production workflow.

Before publishing, `scripts/check_pypi_distribution_state.py` permits only two states:

- `absent`: first publication may proceed;
- `exact_match`: the version already exists and contains exactly the authorized wheel/sdist filenames and SHA-256 values, so this is a safe recovery run.

Any missing file, extra file, duplicate filename, malformed digest, or digest mismatch is `conflict` and fails closed. The workflow does not use blind `skip-existing` recovery.

After Trusted Publishing, `--require-exact` changes the policy: `absent` is no longer acceptable. PyPI must expose exactly the authorized distribution set before the GitHub Release can become public.

## 8. Partial-failure recovery

PyPI and GitHub Release publication cannot be atomically committed. The workflow therefore has explicit recovery semantics.

### Failure before PyPI publication

The GitHub Release, if created, remains a draft. Fix the underlying problem and rerun `publish=true` on the same tag. The workflow may reuse the existing draft only if it is still a draft and its prerelease state matches the package version.

### PyPI succeeded, final GitHub publication failed

Rerun `publish=true` on the same tag. The workflow rebuilds and reauthorizes the same candidate, then queries PyPI. Publication is skipped only when PyPI's existing files exactly match the newly authorized local wheel/sdist bytes. The draft is then eligible for final publication.

### A public GitHub Release already exists

The workflow refuses to mutate it. This is intentional. A release that became public outside the authorization-first transaction requires explicit incident review rather than automated repair.

### Existing PyPI files conflict with the authorized bytes

Stop. Do not overwrite, ignore, or `skip-existing`. Treat the discrepancy as a release integrity incident.

## 9. Environment and permission requirements

Maintain protected GitHub Environments for:

- `sigstore`: permits `id-token: write` only for the signing job and should require maintainer review;
- `pypi`: permits Trusted Publishing and should require maintainer review and appropriate tag restrictions.

The workflow keeps default permissions read-only and elevates narrowly:

- live authorization: `actions: read`, `contents: read`;
- Sigstore: `id-token: write`, `contents: read`;
- draft/final GitHub Release operations: `contents: write` only in those jobs;
- PyPI: `id-token: write`, `contents: read`.

No job receives both GitHub Release write authority and the PyPI Trusted Publishing OIDC permission.

## 10. Consumer verification of released Sigstore artifacts

Example verification for `v1.3.0-rc.1`:

```bash
cosign verify-blob \
  --bundle path/to/open_verification_kernel-1.3.0rc1-py3-none-any.whl.cosign.bundle.json \
  --certificate-identity 'https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.3.0-rc.1' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  path/to/open_verification_kernel-1.3.0rc1-py3-none-any.whl
```

Consumers should trust only the Publish workflow path, exact immutable tag identity, expected issuer, and distribution digest recorded in the authorized ledger.

## Known limitations and claim discipline

- Generic backend routing does not make every external adapter a native proof engine.
- Authorization, infrastructure, workflow, and deployment source extraction remains conservative; incomplete abstraction cannot be promoted into a stronger guarantee.
- FormalPR-Bench is a curated in-repository regression benchmark, not independent external calibration.
- FormalPR-Holdout aggregate evaluation improves label separation but does not by itself establish external validity.
- Independent consumer pin verification establishes concrete integration provenance; it does not substitute for human-adjudicated deployment studies.
- `verified_source_sha` is a release-ledger authorization claim only. Badge, holdout, dogfood, local profile, or declaration-derived evidence must not mint it.
- A signed artifact proves provenance/integrity under the stated Sigstore trust policy; it does not prove the semantic correctness of the software.

## Historical release evidence

Historical releases such as `v1.2.1` remain immutable and retain their original evidence. Their workflow runs, release artifacts, and Sigstore identities are historical facts, not evidence for `v1.3.0-rc.1`.

Independent consumer repositories currently used by the consumer-pin workflow are:

| Consumer | Repository |
|---|---|
| FastAPI + Terraform | `fraware/ovk-consumer-fastapi-terraform` |
| Express + GitHub Actions | `fraware/ovk-consumer-express-actions` |

See [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) and [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) for evidence scopes that go beyond release mechanics.

## Release history

| Version | Changelog |
|---|---|
| v1.3.0-rc.1 (candidate) | [RELEASE_NOTES_v1.3.0-rc.1.md](RELEASE_NOTES_v1.3.0-rc.1.md) |
| v1.2.1 | [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md) |
| v1.2.0 | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

Upgrade paths: [MIGRATION.md](MIGRATION.md).
