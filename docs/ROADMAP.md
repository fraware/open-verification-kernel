# OVK Roadmap

Current release: **v1.2.0**. What OVK can do today: [STATUS.md](STATUS.md). Adoption status: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Release history

| Version | Summary | Changelog |
|---|---|---|
| v1.2.0 | All five check types validated end-to-end; clearer GitHub Action outputs; example rollout workflows | [RELEASE_NOTES_v1.2.0.md](RELEASE_NOTES_v1.2.0.md) |
| v1.1.0 | Realistic PR diff benchmark set; required native checker CI for OPA, Z3, CBMC, Cedar; external rollout guide | [RELEASE_NOTES_v1.1.0.md](RELEASE_NOTES_v1.1.0.md) |
| v1.0.0 | Unified `ovk check`, five check types, ten backends, GitHub Action, benchmark suite | [RELEASE_NOTES_v1.0.0.md](RELEASE_NOTES_v1.0.0.md) |

## What we are working on next

1. **External repository pilots** — publish measured outcomes from real open-source adopters in [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md).
2. **Richer authorization checks** — more expressive Z3 obligations and smaller, clearer counterexamples.
3. **Community backends** — adapters and install docs beyond the current native checker matrix.
4. **CBMC diff depth** — richer extraction from real C PR hunks and repair-loop fixtures for CBMC counterexamples.

## Not planned as product promises

- PyPI publication depends on maintainer release tagging (workflow is ready).
- Optional native checkers (TLA+, Kani, Dafny, Verus, Lean, Alloy) remain non-blocking in CI until their harnesses mature.
