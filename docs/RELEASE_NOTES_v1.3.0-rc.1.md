# OVK v1.3.0-rc.1

Release-candidate notes for the adoption-surface cut. **This file is not attributable publication evidence.** The RC is attributable only after the signed immutable tag, seven tag-bound release-evidence workflows, live release-ledger authorization, Sigstore verification, exact PyPI publication, and final GitHub Release gate in [RELEASE.md](RELEASE.md) have completed.

## Highlights

- Normative capability registry with explicit `release_status` and generated backend tables
- `DecisionState` lattice (`allow` / `block` / `needs_review` / `unknown` / `error` / `skipped`) with fail-closed strict aggregation
- Evidence-integrity envelope with digests, controlling findings, and optional signatures
- Adapter conformance contract; a `stable` label requires the full configured conformance suite
- FormalPR-Bench provenance, partitions, held-out/template-development contamination guards, and version manifest
- Composite Action hardening and SHA-pinned third-party actions on OVK release surfaces
- Candidate-bound source-profile/support-contract infrastructure with strict maturity claims kept below external calibration
- Label-separated FormalPR-Holdout prediction/evaluation with exact prediction-run and digest binding
- Candidate-SHA consumer-pin evidence contract for two independent consumer repositories
- Authorization-first release ledger and Publish workflow: exact candidate → provenance authorization → Sigstore → private draft → PyPI exact read-back → public GitHub Release
- Private GitHub App alpha (`integrations/github-app/`)
- Three advisory pilot reports under `docs/pilots/`
- Generated reviewer TCB inventory: [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md)

## Install

After the attributable RC has actually been published to PyPI:

```bash
pip install open-verification-kernel==1.3.0-rc.1
```

After the immutable tag is attributable, the composite Action may be pinned to that release tag:

```yaml
env:
  OVK_PACKAGE_VERSION: "1.3.0-rc.1"
steps:
  - uses: fraware/open-verification-kernel@v1.3.0-rc.1
```

Before publication, use an audited source checkout or exact commit pin. Do not infer PyPI availability merely from tag existence.

## Engineering preflight

Run on the exact final candidate after the last tree change:

```bash
pytest
python scripts/render_tcb_doc.py --check
python scripts/verify_rc_dod.py
python scripts/verify_rc_install.py
ovk release-preflight
```

The complete development gate additionally includes the six-cell Repro matrix and Native Backends Tier 1 / Tier 1b on that exact SHA.

## Publication evidence still required

Before this document can describe an attributable published RC, maintainers must obtain:

- a GitHub-verified signed annotated `v1.3.0-rc.1` tag on the frozen candidate;
- successful tag-bound `workflow_dispatch` runs for CI, Repro baseline, Native Tier 1, Native Tier 1b, FormalPR-Holdout predict, FormalPR-Holdout eval, and Consumer Pin Verification;
- holdout prediction/evaluation artifacts bound by exact run ID, candidate SHA, prediction digest, and frozen holdout-asset digest;
- both independent consumer artifacts pinning the exact 40-hex candidate SHA;
- a fully authorized release ledger whose authorizer alone mints `verified_source_sha`;
- tag-bound Sigstore signing/verification and tamper tests for the wheel, sdist, and authorized ledger;
- PyPI Trusted Publishing followed by exact filename/SHA-256 read-back;
- final publication of the already-staged GitHub Release only after the PyPI equality gate succeeds.

## Known limits for this RC

- FormalPR-Bench remains an internal regression suite, not independent accuracy calibration.
- Source profiles are not claimed as `externally_calibrated_strict`.
- Several catalog adapters remain experimental/deterministic contract paths rather than native proof execution; see [BACKENDS.md](BACKENDS.md).
- Independent consumer scenario automation does not substitute for the separate human-adjudication program.
- FormalPR-Holdout aggregate evidence does not by itself establish broad external validity.
- Default adoption should begin advisory; strict required-check use remains repository/profile/input specific and calibration dependent.
- Package classifier remains Beta.

See [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md), [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md), and [ROADMAP.md](ROADMAP.md).