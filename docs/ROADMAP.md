# OVK Roadmap

Current product positioning: **`v1.3.0-rc.1` candidate** (typed control plane post-dates signed `v1.2.1`). What OVK can do today: [STATUS.md](STATUS.md). Adoption status: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md). Authoritative program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md).

## Release history

| Version | Summary | Changelog |
|---|---|---|
| v1.3.0-rc.1 (candidate) | Typed backend control plane; P0 trust PRs 1–9 in working tree; publication gates open | [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md) |
| v1.2.1 | Signed release on pre-control-plane commit; consumer pin baseline | [RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md) |
| v1.2.0 | All five check types validated end-to-end; clearer GitHub Action outputs; example rollout workflows | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | Realistic PR diff benchmark set; required native checker CI for OPA, Z3, CBMC, Cedar; external rollout guide | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | Unified `ovk check`, five check types, ten backends, GitHub Action, benchmark suite | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

## What we are working on next

1. **Sprint 0 / attributable gates** — live CI, wheel smoke, Action dogfood, and workflow IDs on a non-`[skip ci]` SHA (P0 code PRs 1–9 already in working tree; see [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md)).
2. **Semantic template conformance v2** and source-profile hardening (Sprints 6–7).
3. **Consumer validation on rc.1** and label-separated holdout (Sprints 8–9).
4. **Attributable publication** of `v1.3.0-rc.1` then `v1.3.0` after the 18-condition gate (Sprint 10).

## Not planned as product promises

- PyPI publication depends on maintainer release tagging (workflow is ready).
- Optional native checkers (TLA+, Kani, Dafny, Verus, Lean, Alloy) remain non-blocking in CI until their harnesses mature.
- Re-attributing `v1.2.1` Sigstore/CI evidence to typed-control-plane commits.
