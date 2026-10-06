# RTK sealed evaluation

Methods freeze and pre-oracle feasibility scaffold for a sealed empirical
evaluation of evidence applicability across verifier and context changes.

This tree lives on branch `research/rtk-sealed-evaluation-507f`. It is methods
and sealed-census work only in the current tip: no oracle labels, RTK
predictions, baseline runs, or unblinding.

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
| External sealed refs | `EXTERNAL_SEALED_REFERENCES.v0.json` | Census byte-bound; anchors/projection pending |
| Sealed census | `sealed/TRANSITION_CENSUS.jsonl` | **BYTE-IDENTICAL** (`b1816276…`) |
| Sealed census manifest | `sealed/TRANSITION_CENSUS_MANIFEST.json` | **BYTE-IDENTICAL** (`c4b1e90e…`) |
| Sealed census provenance | `sealed/SEALED_CENSUS_PROVENANCE.json` | Recorded (artifact 11387510679) |
| Census cardinality probe | `CENSUS_CARDINALITY_PROBE.v0.json` | 248 + sealed bytes verified |
| Pipeline module recovery | `forensics/PIPELINE_MODULE_RECOVERY.v0.json` | **PIPELINE_MODULES_UNAVAILABLE** |
| Source-evidence workflow / tier_v1 / binding | — | **UNCREATED** (authentic modules unavailable) |

## Evaluation phases (ordered)

1. Freeze protocol, schemas, analysis plan, CDI, implementation identity policy, and transition eligibility rules.
2. Bind sealed census bytes (done). Materialize anchors → source evidence → semantic projection → tier_v1 only with authentic modules.
3. Expand only via the frozen candidate list; stop if exhausted below the feasibility gate.
4. Human checkpoint, then oracle (blocked in this phase).
5. Seal cases; run one frozen RTK implementation; analyze predeclared metrics only.

## Tier policy

- Tier A = `REPLAY_VERIFIED` (primary).
- Tier B v1 = `COMMITTED_NATIVE_ATTESTATION` (secondary; do not inflate A; do not treat as worthless).
- Tier B v0 excluded from scoring.
- Local Tier A/B counts: not produced on OVK (authentic pipeline unavailable).

## Honesty constraints

- Sealed census bytes under `sealed/` are the binding census object; do not
  reserialize, regenerate, or replace them with generator output.
- Do not invent sealed anchor/projection digests or fabricate
  `SOURCE_EVIDENCE_V1_BINDING.json`.
- Do not invent materialization/tier modules solely to chase sealed hashes.
- source-universe-v0 identities are permanent; never rewrite v0.
- Go production checker is not an absolute blocker; bounded result is FOUND or
  UNVERIFIED only.
- 20-transition threshold is a feasibility rule, not scientific validity.
- Generator blob check is independent reproducibility only
  (`GENERATOR_BLOB_UNAVAILABLE` recorded).

## Source-evidence v1 (OVK progress)

- Authentic modules installed from handoff transport `de781bad…` (VERIFY.py OK; blobs match).
- Baseline commit lands pre-fix workflow blob `cc374b68…` unchanged; repair commit is **not** byte-identical.
- Materializer executed identity: `f97e2826…`.
- Local pipeline matched frozen anchors `44cb1f27…` and semantic projection `7ea32cb2…`.
- Tier A: 9 anchors / 3 transitions; Tier B v1: 161 anchors / 161 transitions.
- `SOURCE_EVIDENCE_V1_BINDING.json` remains uncreated until repaired-workflow Actions success IDs are recorded (draft at `SOURCE_EVIDENCE_V1_BINDING.DRAFT.json`).
- No oracle / RTK prediction / baseline / unblinding.
