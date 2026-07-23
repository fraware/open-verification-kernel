# OVK v1.2.1

Patch release to close the immutable-tag keyless Sigstore production pin and fix release-gate regressions on `main`.

## Changes

- Publish workflow on an immutable `refs/tags/v1.2.1` Release: build → keyless cosign → verify → attach `*.cosign.bundle.json`
- Composite Action installs sync `ovk/package_data` before `pip install .` so policy schemas ship into site-packages
- Align unit tests with honest CBMC template-harness limits, relative provenance URIs, and reliability-based repo-memory priors

## Install

```bash
pip install open-verification-kernel==1.2.1
```

Or from a checkout:

```bash
pip install -e '.[dev]'
```

## GitHub Action pin

```yaml
env:
  OVK_PACKAGE_VERSION: "1.2.1"
steps:
  - uses: fraware/open-verification-kernel@v1.2.1
```

## Consumer Sigstore verify

```bash
cosign verify-blob \
  --bundle path/to/artifact.cosign.bundle.json \
  --certificate-identity "https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  path/to/artifact.whl
```

Package classifier remains Beta. This release does not claim the full solver-agnostic vision is complete.
