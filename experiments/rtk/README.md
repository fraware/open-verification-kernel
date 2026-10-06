# RTK sealed evaluation

Methods freeze, sealed census, v1 source-evidence binding, and source-universe
expansion attempt for a sealed empirical evaluation of evidence applicability
across verifier and context changes.

This tree lives on branch `research/rtk-sealed-evaluation-507f`. Current tip is
post-expansion checkpoint only: no oracle labels, RTK predictions, baseline
runs, or unblinding.

## What exists on OVK now

| Artifact | Path | Status |
|---|---|---|
| Protocol / analysis plan | `PROTOCOL.md`, `ANALYSIS_PLAN.md` | Present (methods) |
| Eval freeze | `RTK_EVAL_FREEZE.json` | `SOURCE_UNIVERSE_EXPANSION_EXHAUSTED_BELOW_20` |
| Expansion protocol | `SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v1.md` | Frozen methods |
| Candidate list | `SOURCE_REPOSITORY_CANDIDATES.v1.json` | Cutoffs pinned; walk exhausted |
| Source-universe-v1 binding | `SOURCE_UNIVERSE_V1_BINDING.json` | `EXPANSION_EXHAUSTED_NO_ADMITTED_OVERLAY` |
| Expansion walk | `SOURCE_UNIVERSE_V1_EXPANSION_WALK.json` | 5/5 candidates blocked |
| CanonicalDecisionInput.v1 | `schemas/CanonicalDecisionInput.v1.schema.json` + `specs/…canonicalization.md` | Frozen interface |
| Mappings | `mappings/*.v0.json` | Bound from source-evidence v1 |
| Go provenance | `GO_CHECKER_PROVENANCE.v0.md` | **UNVERIFIED** |
| Sealed census | `sealed/TRANSITION_CENSUS.jsonl` | **BYTE-IDENTICAL** (`b1816276…`) |
| Source-evidence v1 binding | `SOURCE_EVIDENCE_V1_BINDING.json` | **BOUND** |

## Evaluation phases (ordered)

1. Freeze protocol, schemas, analysis plan, CDI, implementation identity policy, and transition eligibility rules.
2. Bind sealed census bytes (done). Materialize anchors → source evidence → semantic projection → tier_v1 only with authentic modules (done for v0).
3. Expand only via the frozen candidate list; stop if exhausted below the feasibility gate (**done: exhausted**).
4. Human checkpoint, then oracle (blocked until review).
5. Seal cases; run one frozen RTK implementation; analyze predeclared metrics only.

## Tier policy

- Tier A = `REPLAY_VERIFIED` (primary).
- Tier B v1 = `COMMITTED_NATIVE_ATTESTATION` (secondary; do not inflate A; do not treat as worthless).
- Tier B v0 excluded from scoring.
- Independent REPLAY_VERIFIED transitions after expansion: **3 total** (v0=3, v1=0).

## Source-universe expansion (this checkpoint)

- Cutoffs pinned for five locked expansion candidates before materialization attempts.
- Walked in locked order: pcs-bench → ovk-consumer-fastapi-terraform → ovk-consumer-express-actions → environment-assurance-compiler → lean-project-evidence.
- Each candidate is public with FIRST_PARENT transitions, but authentic `extract_historical_anchors.py` supports only `fraware/CertifyEdge` and `SentinelOps-CI/pcs-core`.
- `generate_transition_census.py` remains UNAVAILABLE; no fabricated overlay census/evidence.
- Feasibility gate: **EXHAUSTED_BELOW_20** (`STOPPED_CANDIDATE_LIST_EXHAUSTED`).
- Study may proceed later only at available sample size with explicit uncertainty/power; oracle not started.

## Honesty constraints

- Sealed census bytes under `sealed/` are the binding census object; do not
  reserialize, truncate, or replace them with generator output.
- source-universe-v0 identities are permanent; never rewrite v0.
- Do not weaken Tier A predicates or invent repository support to chase the gate.
- Go production checker is not an absolute blocker; bounded result is FOUND or
  UNVERIFIED only.
- 20-transition threshold is a feasibility rule, not scientific validity.

## Source-evidence v1 (v0 universe; unchanged)

- Authentic modules installed from handoff transport `de781bad…` (VERIFY.py OK; blobs match).
- Materializer executed identity: `f97e2826…`.
- Tier A: 9 anchors / 3 transitions; Tier B v1: 161 anchors / 161 transitions.
- `SOURCE_EVIDENCE_V1_BINDING.json` **BOUND** at methodology SHA `831a589` via Actions run `37517623512` / job `112454498374`.
- No oracle / RTK prediction / baseline / unblinding.
