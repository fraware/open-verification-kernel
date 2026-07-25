# Trusted Computing Base

Independent-reviewer TCB inventory for Open Verification Kernel (OVK-PR9).
Derived from the normative capability registry (`trusted_components`), composite Action release pins, and the private GitHub App alpha surface.

<!-- BEGIN OVK_TCB_GENERATED -->
Generated for package version **`1.3.0-rc.1`** by `scripts/render_tcb_doc.py`. Do not hand-edit this section; regenerate with `python scripts/render_tcb_doc.py --write`.

## Package identity

| Field | Value |
|---|---|
| Package version | `1.3.0-rc.1` |
| Intended immutable tag | `v1.3.0-rc.1` |
| Public integration path | Composite Action (`action.yml`) + `pip` wheel |
| Private alpha path | `integrations/github-app/` (not Marketplace) |

## Composite Action surface

Third-party actions in release paths must be immutable SHA pins (enforced by `scripts/pin_action_shas.py`):

| File | `uses:` pin | Note |
|---|---|---|
| `action.yml` | `actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830` | v4.3.0 |
| `action.yml` | `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| `.github/workflows/publish.yml` | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `.github/workflows/publish.yml` | `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `.github/workflows/publish.yml` | `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| `.github/workflows/publish.yml` | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `.github/workflows/publish.yml` | `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `.github/workflows/publish.yml` | `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| `.github/workflows/publish.yml` | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `.github/workflows/publish.yml` | `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `.github/workflows/publish.yml` | `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093` | v4.3.0 |
| `.github/workflows/publish.yml` | `sigstore/cosign-installer@d7d6bc7722e3daa8354c50bcb52f4837da5e9b6a` | v3.8.1 |
| `.github/workflows/publish.yml` | `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| `.github/workflows/publish.yml` | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `.github/workflows/publish.yml` | `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093` | v4.3.0 |
| `.github/workflows/publish.yml` | `pypa/gh-action-pypi-publish@ba38be9e461d3875417946c167d0b5f3d385a247` | v1.14.1 (release/v1) |

Floating third-party refs in release paths: **0** (must be zero for RC).

Action install trust boundary:

- Runner installs `open-verification-kernel==$OVK_PACKAGE_VERSION` when set,
  otherwise installs from the Action checkout after `scripts/sync_package_data.py`.
- Consumer repositories must pin the Action to an immutable tag or full commit SHA.
- Check-run emission uses a stable `external_id` bound to repository + head SHA.

## GitHub App surface (private alpha)

The App is **not** part of the default public TCB for adopters who only use the composite Action. Operators who deploy the App additionally trust:

| Control | Implementation |
|---|---|
| Webhook signature verification | HMAC-SHA256 (`X-Hub-Signature-256`); missing/invalid rejected |
| Replay protection | `X-OVK-Timestamp` skew (±300s) + `X-GitHub-Delivery` dedupe store |
| Installation isolation | `{data}/installations/{id}/` partitions for credentials, cache, data |
| Least-privilege permissions | `manifest.json`: `checks:write`, `contents:read`, `pull_requests:read`, `metadata:read` |
| Short-lived installation tokens | On-demand exchange; App JWT ≤10m; installation token ≤1h; no PATs |
| Redacted logs | Paths and secrets scrubbed via `RedactingFilter` |
| Idempotent Check Run updates | `external_id` = `ovk:{repo}:{head_sha}` (same as Action / PR6) |
| No cross-repository cache reuse | Cache keys require `installation_id` + `repo_id` |
| Uninstall cleanup | `installation.deleted` deletes the partition |
| Retention policy | [RETENTION.md](RETENTION.md) |

App code and retention policy: [`integrations/github-app/`](../integrations/github-app/).

## Capability registry trusted components

Every advertised public checker contributes the `trusted_components` list from its `adapters/*/capability.json` entry (after release-status honesty).

| Checker | release_status | Trusted components |
|---|---|---|
| `opa` | `preview` | opa binary; selected Rego policy templates; input extraction / compiler |
| `z3` | `preview` | z3 solver; neutral obligation compiler; encoded abstraction |
| `cbmc` | `preview` | cbmc binary; harness generator or supplied harness; bound configuration |
| `cedar` | `experimental` | deterministic Cedar-shaped evaluator; optional cedar CLI for version probe |
| `tla+` | `experimental` | deterministic state-machine contract evaluator |
| `kani` | `experimental` | deterministic Rust-harness contract evaluator |
| `dafny` | `experimental` | deterministic proof-obligation contract evaluator |
| `verus` | `experimental` | deterministic verified-Rust contract evaluator |
| `lean` | `experimental` | deterministic theorem-obligation contract evaluator |
| `alloy` | `experimental` | deterministic relational-model contract evaluator |
| `lane-self-protection` | `experimental` | self-protection lane evaluator; optional OPA native path |
| `lane-authorization` | `experimental` | authorization lane evaluator; optional Z3 solver |
| `lane-infrastructure` | `experimental` | infrastructure lane evaluator |
| `lane-ci-secrets` | `experimental` | ci_secrets lane evaluator |
| `lane-deployment` | `experimental` | deployment lane evaluator |

### Aggregate trusted-component vocabulary

Union of registry `trusted_components` strings (deduplicated, order of first appearance):

- opa binary
- selected Rego policy templates
- input extraction / compiler
- z3 solver
- neutral obligation compiler
- encoded abstraction
- cbmc binary
- harness generator or supplied harness
- bound configuration
- deterministic Cedar-shaped evaluator
- optional cedar CLI for version probe
- deterministic state-machine contract evaluator
- deterministic Rust-harness contract evaluator
- deterministic proof-obligation contract evaluator
- deterministic verified-Rust contract evaluator
- deterministic theorem-obligation contract evaluator
- deterministic relational-model contract evaluator
- self-protection lane evaluator
- optional OPA native path
- authorization lane evaluator
- optional Z3 solver
- infrastructure lane evaluator
- ci_secrets lane evaluator
- deployment lane evaluator

## Kernel control-plane trust assumptions

Beyond per-adapter tools, an independent reviewer should treat these as in-TCB for strict-mode decisions:

- Decision lattice aggregation (`ovk.core.decision`) and exit-code mapping
- Evidence integrity envelope / digests (`ovk.core.evidence_integrity`)
- Capability + conformance honesty gates (`release_status=stable` requires full suite)
- Trusted policy / metadata provenance loading for self-protection and deployment lanes
- FormalPR-Bench version manifest digests when citing benchmark scores

## Out of TCB (explicit non-claims)

- Unavailable optional native binaries (must not promote to allow in strict mode)
- Floating `@main` Action pins or unverified PyPI builds without matching tag evidence
- Human pilot ledgers and advisory pilot fixture metrics (evidence for adoption, not TCB)
- Re-attributing signed `v1.2.1` Sigstore evidence to this RC source tree
<!-- END OVK_TCB_GENERATED -->
