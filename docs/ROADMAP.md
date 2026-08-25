# OVK Roadmap

Current product positioning: **`v1.3.0-rc.1` engineering candidate** on branch `hardening/full-vision-2026-08-24` (package `1.3.0-rc.1`; completion-program work in this tree post-dates signed `v1.2.1` and is not yet an attributable tag). What OVK can do today: [STATUS.md](STATUS.md). Adoption status: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md). TCB: [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md). Authoritative program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md).

## Release history

| Version | Summary | Changelog |
|---|---|---|
| v1.3.0-rc.1 (engineering candidate) | Adoption surface PR1–PR9 plus completion-program compilers/contracts/ledger work; live attributable tag pending | [RELEASE_NOTES_v1.3.0-rc.1.md](RELEASE_NOTES_v1.3.0-rc.1.md) |
| v1.2.1 | Signed release on pre-control-plane commit; consumer pin baseline | [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md) |
| v1.2.0 | All five check types validated end-to-end; clearer GitHub Action outputs; example rollout workflows | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | Realistic PR diff benchmark set; required native checker CI for OPA, Z3, CBMC, Cedar; external rollout guide | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | Unified `ovk check`, five check types, ten backends, GitHub Action, benchmark suite | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

## Completed in this working tree (OVK-PR1–PR9)

1. Normative capability registry + multi-OS repro baseline harness.
2. DecisionState lattice with strict fail-closed truth tables.
3. Evidence integrity envelope (digests / controlling findings).
4. Seven-item adapter conformance; stable ⊆ conformant.
5. FormalPR-Bench provenance, partitions, contamination guards, version manifest.
6. Action hardening suite + immutable SHA pins for release-path third parties.
7. GitHub App private alpha with required security controls.
8. Three advisory pilot reports under `docs/pilots/`.
9. RC metadata (`1.3.0-rc.1`), TCB doc, DoD + install verification scripts.

## What we are working on next

1. **Attributable publication of `v1.3.0-rc.1`** — non-`[skip ci]` workflow IDs, release ledger authorization of `verified_source_sha`, signed tag, Publish/Sigstore, consumer remotes on the immutable pin ([ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md)).
2. **Promotion path to `v1.3.0`** — after the 18-condition gate, independent consumer validation, and attributable holdout aggregates.
3. Ongoing calibration of strict lanes on real diffs (advisory remains the default recommendation until attributable RC evidence exists). FormalPR-Bench remains regression-only.

## Not planned as product promises

- PyPI publication depends on maintainer release tagging (workflow is ready).
- Optional native checkers (TLA+, Kani, Dafny, Verus, Lean, Alloy) remain non-blocking in CI until their harnesses mature.
- Re-attributing `v1.2.1` Sigstore/CI evidence to typed-control-plane commits.
- Claiming `externally_calibrated_strict` from local dogfood or FormalPR-Bench alone.
