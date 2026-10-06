# RTK sealed evaluation

Methods freeze and pre-oracle feasibility scaffold for a sealed empirical
evaluation of evidence applicability across verifier and context changes.

This tree lives on branch `experiment/rtk-sealed-evaluation`. It is methods
work only in the current commit: no oracle labels, RTK predictions, baseline
runs, or unblinding.

## What exists on OVK now

| Artifact | Path | Status |
|---|---|---|
| Protocol / analysis plan | `PROTOCOL.md`, `ANALYSIS_PLAN.md` | Present (methods) |
| Eval freeze | `RTK_EVAL_FREEZE.json` | `PRE_ORACLE_FEASIBILITY_AMENDMENT` |
| Expansion protocol | `SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v1.md` | Frozen methods |
| Candidate list | `SOURCE_REPOSITORY_CANDIDATES.v1.json` | Frozen before added-repo inspection |
| CanonicalDecisionInput.v1 | `schemas/CanonicalDecisionInput.v1.schema.json` + `specs/…canonicalization.md` | Frozen interface |
| Mapping stubs | `mappings/*.v0.json` | `PENDING_SOURCE_MATERIALIZATION` |
| Go provenance | `GO_CHECKER_PROVENANCE.v0.md` | **UNVERIFIED** |
| External sealed refs | `EXTERNAL_SEALED_REFERENCES.v0.json` | Recorded, not locally validated |
| Census cardinality probe | `CENSUS_CARDINALITY_PROBE.v0.json` | 248 cardinality match; digest mismatch |
| Source-evidence workflow / tier_v1 / binding | — | **UNCREATED** |

## Evaluation phases (ordered)

1. Freeze protocol, schemas, analysis plan, CDI, implementation identity policy, and transition eligibility rules.
2. Materialize source-universe-v0 from public cutoffs (PENDING on OVK until sealed digests reproduce).
3. Expand only via the frozen candidate list; stop if exhausted below the feasibility gate.
4. Human checkpoint, then oracle (blocked in this phase).
5. Seal cases; run one frozen RTK implementation; analyze predeclared metrics only.

## Tier policy

- Tier A = `REPLAY_VERIFIED` (primary).
- Tier B v1 = `COMMITTED_NATIVE_ATTESTATION` (secondary; do not inflate A; do not treat as worthless).
- Tier B v0 excluded from scoring.
- Local Tier A/B counts: not produced on OVK in this phase.

## Honesty constraints

- Do not invent sealed census/anchor/projection digests or fabricate
  `SOURCE_EVIDENCE_V1_BINDING.json`.
- External digests may be recorded only with
  `EXTERNAL_REPORT_UNVERIFIED_ON_OVK` provenance until regenerated identically.
- source-universe-v0 identities are permanent; never rewrite v0.
- Go production checker is not an absolute blocker; bounded result is FOUND or
  UNVERIFIED only.
- 20-transition threshold is a feasibility rule, not scientific validity.
