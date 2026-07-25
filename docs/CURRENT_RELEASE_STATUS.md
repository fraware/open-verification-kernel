# OVK Release Status

Living adoption dashboard for Open Verification Kernel.

**Last updated:** 2026-07-25

**Release judgment:** **`v1.3.0-rc.1` in-repo release candidate**. Package metadata is `1.3.0-rc.1`. The typed backend control plane and adoption-surface program (OVK-PR1–PR9) post-date signed `v1.2.1` (`a27d5720f4350c00bca34f71d991c31f5a2f38c7`). Default product path remains shadow/legacy-authoritative; enforced routing is lane-policy opt-in until attributable publication closes. Do not treat current `main` as a re-validation of signed `v1.2.1`.

Authoritative audit: [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md). Engineering program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md). TCB: [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md). Historical: [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) (superseded for day-to-day status).

## At a glance

| Signal | Current state |
|---|---|
| **Package version** | Working tree / RC metadata: `1.3.0-rc.1` (intended tag `v1.3.0-rc.1`); signed immutable tag remains `v1.2.1` only for that tag’s commit |
| **FormalPR-Bench** | Provenance + partitions + version manifest (`benchmarks/formal_pr_bench/manifest.v1.json`); cite `benchmark_version` separately from `verified_source_sha` |
| **Check types** | Five bounded production lanes: self-protection, authorization, infrastructure, CI secrets, deployment |
| **Backend execution** | Typed `BackendControlPlane` + `route_obligation`; five policy-selectable enforced lanes via `adapter_runtime` |
| **Capability registry** | Every advertised checker in `adapters/*/capability.json`; `stable ⊆` full seven-item conformance |
| **Decision / evidence** | Normative `DecisionState` lattice; integrity envelope with controlling-finding reconstruction |
| **Unit and workflow tests** | In-repo suites green locally; live GitHub Actions workflow IDs still pending on a non-`[skip ci]` SHA |
| **Package portability** | `scripts/verify_rc_install.py` covers Action SHA pins + metadata; `--wheel` builds/imports outside checkout |
| **GitHub Action** | Composite Action SHA-pins third-party deps (PR6); consumers still live-pin `v1.2.1` until rc.1 tag exists |
| **External validation** | Three advisory pilot reports under `docs/pilots/` (≥2 with full workflow reproduction) |
| **GitHub App** | Private alpha under `integrations/github-app/` (not Marketplace) |
| **Sigstore** | Immutable-tag E2E closed for `v1.2.1` only — not attributable to typed-control-plane / RC commits |

OVK is not complete formal verification of arbitrary code. It provides explainable, conservative checks for a bounded set of high-risk changes and emits explicit unknown and human-review outcomes.

## Adoption-surface program (OVK-PR1–PR9)

| PR | Scope | In-repo status |
|---|---|---|
| PR1 | Multi-OS repro baseline + normative capability/template registry | Complete |
| PR2 | DecisionState lattice + truth tables | Complete |
| PR3 | Evidence integrity envelope | Complete |
| PR4 | Adapter conformance matrix; stable ⊆ conformant | Complete |
| PR5 | FormalPR-Bench provenance / partitions / version manifest | Complete |
| PR6 | Action scenario hardening + SHA-pinned third parties | Complete |
| PR7 | GitHub App private alpha | Complete |
| PR8 | Three advisory pilot reports | Complete |
| PR9 | RC cut prep, TCB doc, attributable gates, install verification | **In-repo ready** (live tag/Sigstore pending) |

Local DoD verifier: `python scripts/verify_rc_dod.py`. Install surface: `python scripts/verify_rc_install.py` (add `--wheel` for outside-checkout import).

## Source SHA terminology

| Field | Meaning | When to set |
|---|---|---|
| `benchmark_source_sha` | Commit whose FormalPR-Bench (or badge) artifacts were measured | Any bench/badge run |
| `verified_source_sha` | Commit with a **complete observed required-workflow set** | Only after Sprint 0 / release gates attach live workflow IDs |

Badge-only or `[skip ci]` commits must set `benchmark_source_sha` and must **not** be labeled `verified_source_sha`.

## Local Sprint 0 / RC baseline

Local evidence only. Distinguishes from GitHub Actions workflow IDs (still pending).

Multi-OS reproducible baselines (OVK-01): see [REPRO_BASELINE.md](REPRO_BASELINE.md) and the [`repro-baseline`](../.github/workflows/repro-baseline.yml) workflow. Records are uploaded by CI (see [baselines/README.md](baselines/README.md)); the directory may be empty until maintainers download or commit matrix artifacts.

| Gate | Command | Notes |
|---|---|---|
| Release metadata | `python scripts/check_release_metadata.py` | Must equal `1.3.0-rc.1` |
| RC DoD (in-repo) | `python scripts/verify_rc_dod.py` | Program DoD minus live publication |
| RC install (static) | `python scripts/verify_rc_install.py` | Action SHA pins + package metadata |
| RC install (wheel) | `python scripts/verify_rc_install.py --wheel` | Optional; needs `build` |
| TCB freshness | `python scripts/render_tcb_doc.py --check` | Regenerates via `--write` |
| Release preflight | `ovk release-preflight` | Includes RC DoD + install + TCB |

### Still pending (live GitHub Actions / secrets) — maintainer publication

| Gate | Status | Evidence |
|---|---|---|
| General CI / unit+gates on non-`[skip ci]` SHA | Pending live run | Record run URL → `verified_source_sha` |
| Native Tier 1 | Pending | — |
| Action dogfood | Pending | — |
| Expanded FormalPR-Bench on release SHA | Pending | Use `benchmark_source_sha` |
| Adversarial release-bundle in Actions | Pending | Local `verify_release_bundle.py` entrypoint present |
| Label-separated holdout live eval | Pending | Needs `HOLDOUT_DOWNLOAD_TOKEN` + `HOLDOUT_ASSET_SHA256` |
| Consumer remotes on `v1.3.0-rc.1` | Pending tag + push | Template targets rc.1; live remotes still on `v1.2.1` |
| Signed tag + Publish/Sigstore for rc.1 | Pending | Do not re-attribute `v1.2.1` cosign evidence |

## Adoption readiness

| Mode | Current recommendation | Conditions |
|---|---|---|
| **Local/demo** | Appropriate after current local/CI green | Use shipped examples and inspect assumptions and limits |
| **Advisory Action** | Appropriate for pilots on pinned tags | Prefer signed `v1.2.1` until `v1.3.0-rc.1` is attributable; collect FPs/unknowns |
| **Strict required check** | Repository-specific only | Calibrate on real diffs; trusted abstraction sources; protected policy metadata |
| **Production-stable general enforcement** | Not yet | Needs attributable rc.1 (or later), consumer pins, and Sprint 0 live gates |

Suggested rollout: local validation → advisory artifacts → advisory check run/comment → calibrated strict lane → protected required check.

## P0 trust defects (R2 PRs 1–9) — working-tree status

Code for R2 P0 PRs 1–9 is present in this working tree. Historical defect inventory: [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md). Program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md).

**Still open for attributable release:** live non-`[skip ci]` workflow IDs, consumer repo pins on immutable rc.1, label-separated holdout aggregates, and signed publication gates — see [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md).

## Maintainer release gates

Before tagging or publishing **`v1.3.0-rc.1`**:

- [x] package version / `__version__` / release metadata align on `1.3.0-rc.1`
- [x] TCB documented ([TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md))
- [x] in-repo RC DoD (`scripts/verify_rc_dod.py`) and Action/pip install surface (`scripts/verify_rc_install.py`)
- [ ] run all CI and native Tier 1 jobs on a non-`[skip ci]` source commit;
- [ ] confirm wheel smoke from a directory outside the checkout on that SHA;
- [ ] confirm automatic-diff composite Action dogfood;
- [ ] confirm package version matches the release tag (`v1.3.0-rc.1`);
- [ ] run full expanded FormalPR-Bench and release preflight;
- [ ] validate a complete release bundle, including evidence-quality semantics;
- [ ] exercise HMAC signing and identity-bound Sigstore signing according to release policy;
- [ ] run the immutable Action or release wheel in both independent consumer repositories at the rc.1 pin;
- [ ] update status with exact `verified_source_sha` and workflow links;
- [ ] keep the package classifier at Beta until independent pilots and P0 closure meet the production gate.

Promotion to **`v1.3.0`** additionally requires P0 closure + consumer + holdout evidence per [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md). Do not re-attribute `v1.2.1` Sigstore evidence to typed-control-plane commits.

## Related documents

| Document | Purpose |
|---|---|
| [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md) | Reviewer TCB inventory (registry + Action/App) |
| [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md) | Sprint 10 / RC publication gate |
| [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md) | Authoritative R2 deep audit |
| [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md) | Sprint/PR execution program |
| [SOURCE_PROFILE_HARDENING.md](SOURCE_PROFILE_HARDENING.md) | Sprint 6 profile status |
| [HOLDOUT_LABEL_SEPARATION.md](HOLDOUT_LABEL_SEPARATION.md) | Sprint 8 prediction/eval split |
| [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) | Sprint 9 consumer pins |
| [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) | Historical pre-control-plane audit |
| [STATUS.md](STATUS.md) | Command and lane inventory |
| [BACKENDS.md](BACKENDS.md) | Exact backend execution maturity and guarantee classes |
| [REPRO_BASELINE.md](REPRO_BASELINE.md) | Multi-OS reproducible baseline harness (OVK-01) |
| [INTEGRATION.md](INTEGRATION.md) | Installation and GitHub Action setup |
| [RELEASE.md](RELEASE.md) | Maintainer release procedure |
| [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) | Independent advisory pilot process |
| [pilots/README.md](pilots/README.md) | Published OVK-PR8 advisory pilot reports |
| [BENCHMARK.md](BENCHMARK.md) | Internal benchmark format and execution |
