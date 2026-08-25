# Attributable Publication Checklist (Sprint 10 / OVK-PR9)

Gate for publishing **`v1.3.0-rc.1`** and later promoting to **`v1.3.0`**.
Authority: [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md) 18-condition gate.
Status dashboard: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md). TCB: [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md).
Release procedure: [RELEASE.md](RELEASE.md). Consumer pins: [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md).

## Terminology

| Field | Use |
|---|---|
| `benchmark_source_sha` | FormalPR-Bench / badge measurement identity |
| `verified_source_sha` | Complete observed required-workflow set only |

Never label a `[skip ci]` badge commit as verified. Never re-attribute `v1.2.1`
Sigstore / consumer evidence to typed-control-plane commits. FormalPR-Bench and
in-repo dogfood do not authorize `verified_source_sha`; that field is release-ledger only.

## In-repo readiness (OVK-PR9) — complete without live secrets

Run these locally before asking maintainers for a tag:

```bash
python scripts/check_release_metadata.py
python scripts/render_capability_tables.py --check
python scripts/render_tcb_doc.py --check
python scripts/validate_capabilities.py
python scripts/validate_adapter_conformance.py
python scripts/verify_rc_dod.py
python scripts/verify_rc_install.py          # Action SHA pins + package metadata
python scripts/verify_rc_install.py --wheel  # outside-checkout wheel import
ovk release-preflight
```

| Item | Status |
|---|---|
| Package / `__version__` / metadata = `1.3.0-rc.1` | Done in working tree |
| Registry covers every public checker; `stable ⊆` conformant | Done (DoD script) |
| Strict fail-closed lattice + evidence integrity suites present | Done (PR2+PR3) |
| Evidence reconstructs controlling decision APIs | Done |
| Bench version manifest + partition digests | Done (PR5) |
| ≥2 pilot reports under `docs/pilots/` | Done (PR8; three published) |
| TCB doc generated from registry + Action/App surfaces | Done |
| Installable via pip wheel path **and** composite Action (SHA-pinned deps) | In-repo verified; PyPI/tag still live |

## Exact maintainer publication sequence (requires push + secrets)

Replace `<SOURCE_SHA>` with a **non-`[skip ci]`** commit that carries this tree.
Do **not** tag from a badge-only commit.

### 1. Land source and observe required workflows

```bash
# After push to origin (this workspace does not push):
git push origin HEAD:main   # or open/merge a PR — maintainer only

# Confirm the commit message does NOT contain [skip ci]
git log -1 --format=%B <SOURCE_SHA>
```

Required workflow names (collector): `CI`, `Native Tier 1`, `Release`, `Bench`
(plus Action dogfood / wheel smoke as recorded in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)).

```bash
python scripts/collect_workflow_evidence.py \
  --sha <SOURCE_SHA> \
  --output .verification/workflow-evidence-<SOURCE_SHA>.json

# Optional direct inspection:
gh run list --repo fraware/open-verification-kernel --commit <SOURCE_SHA> --limit 30 \
  --json databaseId,workflowName,status,conclusion,url,headSha
```

Only after the complete required set is green on `<SOURCE_SHA>`, set
`verified_source_sha=<SOURCE_SHA>` in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)
and paste run URLs / IDs. Until then cite `benchmark_source_sha` only.

### 2. Signed immutable tag + GitHub Release

Tag binding: Publish requires `github.event.release.tag_name` (without leading `v`)
to equal `ovk.__version__` exactly — tag **`v1.3.0-rc.1`**, package **`1.3.0-rc.1`**.

```bash
git fetch origin
git checkout <SOURCE_SHA>
git tag -s v1.3.0-rc.1 <SOURCE_SHA>
git push origin v1.3.0-rc.1

gh release create v1.3.0-rc.1 \
  --verify-tag \
  --title "OVK v1.3.0-rc.1" \
  --notes-file docs/RELEASE_NOTES_v1.3.0-rc.1.md
```

Do not move historical tags (`v1.2.1`, …).

### 3. Sigstore / cosign (identity-bound)

Protected Publish workflow (`.github/workflows/publish.yml`) keyless-signs distributions
in the `sigstore` environment. Production verification identity for this RC:

```text
https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.3.0-rc.1
```

OIDC issuer:

```text
https://token.actions.githubusercontent.com
```

```bash
# Watch the Publish run attached to the Release:
gh run list --repo fraware/open-verification-kernel --workflow Publish.yml --limit 5

# Consumer-side verify (after downloading wheel + *.cosign.bundle.json from the Release):
export OVK_COSIGN_IDENTITY='https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.3.0-rc.1'
export OVK_COSIGN_ISSUER='https://token.actions.githubusercontent.com'
cosign verify-blob \
  --bundle path/to/artifact.cosign.bundle.json \
  --certificate-identity "$OVK_COSIGN_IDENTITY" \
  --certificate-oidc-issuer "$OVK_COSIGN_ISSUER" \
  path/to/open_verification_kernel-1.3.0rc1-*.whl
```

Optional dry-run (no PyPI; **not** a production pin — bound to branch ref, not the tag):

```bash
gh workflow run Publish.yml --ref main -f dry_run=true
gh run watch
```

### 4. Consumer pin bumps (separate remotes; do not push from this workspace alone)

In-repo templates already target `v1.3.0-rc.1`
([templates/consumer_validation.workflow.yml](templates/consumer_validation.workflow.yml),
[examples/github_workflows/](../examples/github_workflows/)).

After the tag exists, in each consumer:

```bash
# Example for fastapi consumer (repeat for express):
gh api repos/fraware/ovk-consumer-fastapi-terraform/contents/.github/workflows/ \
  --jq '.[].name'   # locate validation workflow

# Bump uses: fraware/open-verification-kernel@v1.3.0-rc.1
# and OVK_PACKAGE_VERSION: "1.3.0-rc.1" via PR, then:
gh workflow run "OVK Consumer Validation" --repo fraware/ovk-consumer-fastapi-terraform
gh workflow run "OVK Consumer Validation" --repo fraware/ovk-consumer-express-actions

gh run list --repo fraware/ovk-consumer-fastapi-terraform --limit 5
gh run download <RUN_ID> --repo fraware/ovk-consumer-fastapi-terraform \
  -n <evidence-artifact-name> -D ./consumer-evidence/fastapi/
```

Full checklist: [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md).

### 5. Record status

Update [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) with:

- `verified_source_sha`
- CI / Native Tier 1 / Action dogfood / Publish workflow IDs + URLs
- Sigstore identity string for `v1.3.0-rc.1`
- Consumer pin SHAs / run URLs

## Pre-tag checklist (`v1.3.0-rc.1`) — remaining maintainer actions

- [x] Adoption-surface PRs 1–9 landed in the working tree (in-repo)
- [ ] Non-`[skip ci]` CI, native Tier 1, wheel smoke, Action dogfood, release preflight green on the tag source
- [ ] Expanded FormalPR-Bench recorded with `benchmark_source_sha`
- [ ] Template conformance v2 matrix regenerated from semantic statuses (as needed on release SHA)
- [ ] Both consumers dispatched on immutable rc.1 pin (or audited commit); evidence downloaded and verified
- [ ] Label-separated holdout aggregates retained when promoting beyond RC (predictions digest + eval workflow IDs)
- [ ] Release artifacts signed; workflow IDs and digests recorded in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)

## Promote to `v1.3.0`

Only after:

- [ ] All 18 completion-gate conditions hold
- [ ] P0 closure (R2 PRs 1–9) on the exact tag source
- [ ] Consumer validation on the exact pin
- [ ] Attributable holdout aggregates (predictions digest + eval)
- [ ] Human pilot ledgers remain separate from automated fixtures
- [ ] No re-attribution of `v1.2.1` Sigstore evidence to typed-control-plane commits

## Blocked without external access

Live GitHub Actions run URLs, consumer repo pin PRs, protected Publish/Sigstore environments,
and private holdout evaluation require maintainer credentials outside this working tree.
