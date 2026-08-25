# OVK v1.3.0-rc.1

Release-candidate notes for the adoption-surface cut. **Do not treat this document as attributable publication evidence** until a signed immutable tag exists and [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md) live gates are filled.

## Highlights

- Normative capability registry with honest `release_status` and generated backend tables
- DecisionState lattice (`allow` / `block` / `needs_review` / `unknown` / `error` / `skipped`) with strict fail-closed aggregation
- Evidence integrity envelope (digests, timestamps, controlling findings, optional signature)
- Seven-item adapter conformance; `stable` requires full suite
- FormalPR-Bench provenance, partitions, mutations/held-out guards, version manifest
- Composite Action hardening + SHA-pinned third-party actions in release paths
- Private GitHub App alpha (`integrations/github-app/`)
- Three advisory pilot reports under `docs/pilots/`
- Reviewer TCB inventory: [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md)

## Install (after the tag exists)

```bash
pip install open-verification-kernel==1.3.0-rc.1
```

Composite Action (immutable pin):

```yaml
env:
  OVK_PACKAGE_VERSION: "1.3.0-rc.1"
steps:
  - uses: fraware/open-verification-kernel@v1.3.0-rc.1
```

Until the tag is published, local/dev installs remain `pip install -e '.[dev]'` from this tree; the Action falls back to checkout install when PyPI lacks the RC.

## Local RC preflight

```bash
python scripts/verify_rc_dod.py
python scripts/verify_rc_install.py
ovk release-preflight
```

## Known limits for this RC

- Live non-`[skip ci]` workflow IDs and Sigstore identity for **this** version are not yet recorded
- Independent consumers still pin signed `v1.2.1` until remotes are bumped
- Default product path remains advisory / shadow until attributable strict-mode calibration
- Package classifier remains Beta

See [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) and [ROADMAP.md](ROADMAP.md).
