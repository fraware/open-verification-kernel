# Source Universe Expansion Protocol v2

Status: **pre-oracle expansion walk complete** under the frozen v2 adapter
contract. Gate: `EXHAUSTED_BELOW_20`. No oracle labeling. No RTK prediction
execution. No baseline execution. No unblinding.

Amendment identity: `source_universe_expansion_protocol_v2_materialization`.
Related interface freeze: `source_universe_expansion_protocol_v2_adapter_interface`.

## Purpose

Define **repository-independent source-side adapters** for enumerating and
admitting historical transitions into the RTK sealed evaluation source universe
**after** source-universe-v0 and the exhausted v1 expansion walk are recorded,
and **before** any oracle work begins.

v2 does not rewrite v0 or v1. It amends the *mechanism* by which already-frozen
expansion candidates may be processed under uniform admission rules.

## Why v2 exists

v1 candidate eligibility (public FIRST_PARENT history at pinned cutoffs) and the
authentic extractor's closed repository dispatch were inconsistent:

- `SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v1.md` and
  `SOURCE_REPOSITORY_CANDIDATES.v1.json` treat five expansion repositories as
  source-side eligible once public history and cutoffs are pinned.
- Authentic `extract_historical_anchors.py` (blob `f37323df…`) only dispatches
  `fraware/CertifyEdge` and `SentinelOps-CI/pcs-core`, and exits with
  `unsupported frozen repository` for every other identity.
- `generate_transition_census.py` remains unrecovered (`GENERATOR_BLOB_UNAVAILABLE`).

The v1 walk therefore exhausted the locked candidate list with zero overlay
admissions (`SOURCE_UNIVERSE_V1_EXPANSION_WALK.json`,
`SOURCE_UNIVERSE_V1_BINDING.json`). That exhaustion record is immutable.

v2 replaces closed `elif repository == …` dispatch with a generic adapter
contract so every frozen candidate can be attempted under the **same declared
admission rules**, including candidates that yield zero admissible cases.

## Non-goals

- Does not authorize oracle construction, RTK prediction, baseline execution, or
  unblinding.
- Does not rewrite source-universe-v0 identities, sealed census bytes, v1
  binding, or authentic v0 extractor/materializer blobs.
- Does not add, delete, or reorder the five expansion candidates or their
  pinned cutoffs during v2.
- Does not invent overlay census/evidence bytes in the interface-freeze pass.
- Does not claim new census code is recovered or authentic v0.
- Does not tune predicates or adapters for cardinality.
- Does not weaken Tier A, substitute attestation for replay, or promote Tier B
  into Tier A.

## Preserved identities (verbatim)

### Source-universe-v0 (immutable)

As recorded in `SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v1.md` and
`SOURCE_REPOSITORY_CANDIDATES.v1.json`:

| Repository | URL | Cutoff SHA | History rule |
|---|---|---|---|
| CertifyEdge | https://github.com/fraware/CertifyEdge | `6ef02d54c4697886b20577f10eec683861475db2` | FIRST_PARENT |
| pcs-core | https://github.com/SentinelOps-CI/pcs-core | `9c971f5f9da8a424924dd8f48d6a3b71a1009e1b` | FIRST_PARENT |

Sealed v0 digests remain binding (see `EXTERNAL_SEALED_REFERENCES.v0.json`,
`SOURCE_EVIDENCE_V1_BINDING.json`):

- census SHA-256 `b1816276176297adf345981fe5d9c8271cf00f5b71653d59a21d8261d64a6b11`
- anchors SHA-256 `44cb1f2701705375e9354b4a51a07064d2dba2d33f757e0955fc03db00d4d5cc`
- semantic projection SHA-256 `7ea32cb2c579077f281a3356683a3e926872492b6e756b44c0c39d077358f1fe`

### Source-universe-v1 (immutable exhaustion record)

- Protocol: `SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v1.md`
- Candidates: `SOURCE_REPOSITORY_CANDIDATES.v1.json` (cutoffs pinned at `13b1ae5…`)
- Walk: `SOURCE_UNIVERSE_V1_EXPANSION_WALK.json`
- Binding: `SOURCE_UNIVERSE_V1_BINDING.json` (`EXPANSION_EXHAUSTED_NO_ADMITTED_OVERLAY`)
- Freeze amendment: `source_universe_expansion_exhausted_below_20`

v1 remains the permanent record that the authentic closed-dispatch procedure
could not admit the five candidates. v2 does not erase or rewrite that fact.

### Frozen expansion candidates (no add / delete / reorder)

Order and cutoffs remain exactly as in `SOURCE_REPOSITORY_CANDIDATES.v1.json`:

1. `pcs-bench` @ `6092cccefee7841dfde1393e6881d433838a2252`
2. `ovk-consumer-fastapi-terraform` @ `784576bc5fd01ac80092662887a896301d4fe186`
3. `ovk-consumer-express-actions` @ `31aed31a04c7bca67d3bd6151caf1e42f4b7d1f8`
4. `environment-assurance-compiler` @ `812b4b13f8acdfcafb50de9d794c7fa0b20b31ad`
5. `lean-project-evidence` @ `4660d97db933b0fbcf5c9af466191055c887bea3`

During v2: **do not** insert, delete, or reorder these five. Changing the
candidate set requires a new candidates file version and a new freeze amendment.

## Generic adapter contract

Adapters live under
`experiments/p05_formalpr_bench/rtk_eval/expansion_v2/`.

A source repository adapter exposes, at minimum:

1. **Deterministic transition enumeration** (FIRST_PARENT up to cutoff)
2. **Governed-artifact discovery** (source-side paths / artifact classes)
3. **Historical claim-anchor extraction**
4. **Source-evidence candidate discovery**
5. **Source-revision native-validator execution**
6. **Subject binding**
7. **Evidence-snapshot construction**

Adapters **must never**:

- import or invoke RTK
- execute target-revision validators
- read oracle labels
- consult unblinded information
- invent attestation as a substitute for `REPLAY_VERIFIED`

See `expansion_v2/adapter_contract.py` and `expansion_v2/README.md`.

## Census machinery v2 (explicitly new)

Because authentic `generate_transition_census.py` is unrecovered, v2 introduces
**new** module `generate_transition_census_v2.py`.

This module is **not** claimed to be recovered or authentic v0. It is designed to:

- enumerate the complete FIRST_PARENT universe for each already-frozen candidate
- retain exclusions with declared reason codes
- content-address outputs (SHA-256 of canonical JSONL + manifest)

Interface-freeze pass: module skeleton + output schema documentation only.
**Do not** invent overlay census bytes for the five candidates as if
materialization ran.

## Required sequence (freeze before materialization)

1. **Freeze** the generic adapter interface, reason-code schema, and contract
   tests (this amendment / this pass).
2. **Pass** the v0 compatibility test on CertifyEdge and pcs-core overlapping
   supported surface (semantic equivalence to sealed v0 anchors/evidence;
   byte identity not required unless separately contracted). Semantic divergence
   is a **blocker** for external expansion.
3. **Only then** implement repository-specific semantic mapping and process the
   five frozen expansion candidates under identical admission rules.
4. Process every candidate, including those that yield zero admissible cases.
   Do not skip a candidate because a prior candidate yielded zeros.

Steps 3–4 are **out of scope** for the interface-freeze pass.

## v0 compatibility requirement

Before any external (non-v0) expansion materialization under v2:

- Feed CertifyEdge and pcs-core through the new adapter mechanism.
- Require **semantic equivalence** to sealed v0 anchors / evidence / semantic
  projection for the overlapping supported surface.
- Byte identity of intermediate JSONL is **not** required unless a separate
  contract demands it.
- Any semantic divergence blocks external expansion until resolved without
  weakening Tier A or chasing cardinality.

The compatibility harness is
`expansion_v2/tests/test_v0_compatibility.py`. Until v0 adapters are
implemented, the harness may skip with reason `ADAPTER_NOT_YET_IMPLEMENTED`,
but the requirement and sealed digests it will check are declared now.

## Admission rules (uniform)

For each frozen expansion candidate, under the same declared rules:

1. Clone/public checkout at the pinned cutoff SHA.
2. Enumerate complete FIRST_PARENT transitions via the adapter census path.
3. Apply source-side eligibility only (repository state; not RTK/oracle).
4. Retain every exclusion with a reason code from the frozen reason-code set.
5. Extract anchors / discover evidence / run source-revision native validators
   only through the adapter contract.
6. Append admitted records to an **expansion overlay**; never mutate
   source-universe-v0 artifacts.
7. Count independent `REPLAY_VERIFIED` transitions added (Tier A only).

Zero admissible cases is a valid outcome and must be recorded, not skipped.

## Stopping rule (predeclared)

Carry forward the feasibility gate:

- Target: **≥ 20** independent `REPLAY_VERIFIED` transitions
  (v0 + v1/v2 overlay), feasibility rule only — not scientific validity.
- Stop early if the gate is met while walking the frozen ordered list.
- If the ordered list is **exhausted** and the total remains below 20:
  **STOP**. Do not search indefinitely for further repositories.
  Record `expansion_status: STOPPED_CANDIDATE_LIST_EXHAUSTED` (or equivalent
  v2 walk status). Do not run the oracle in this phase.

Current baseline before any v2 materialization: v0 contributes 3 independent
`REPLAY_VERIFIED` transitions; v1 overlay contributed 0.

## Tier A preservation (exact)

- Tier A = `REPLAY_VERIFIED` — **primary scoring set**.
- Tier B v1 = `COMMITTED_NATIVE_ATTESTATION` — secondary scoring; **do not
  inflate Tier A**; do not treat Tier B as worthless.
- Tier B v0 remains excluded from scoring.
- **No attestation substitution** for Tier A.
- **No Tier B promotion** into Tier A.
- **Do not weaken** Tier A predicates to chase the feasibility gate.
- Tier labels are assigned only after source-evidence materialization exists
  under the frozen v2 adapters; until then overlay tier counts remain
  unproduced.

## Relationship to authentic v0 modules

Authentic blobs remain the immutable v0 pipeline record:

| Module | Blob (abbrev.) | Policy |
|---|---|---|
| `extract_historical_anchors.py` | `f37323df…` | **Do not edit** |
| `materialize_source_evidence.py` | `f97e2826…` | **Do not edit** |
| `project_source_evidence_semantics.py` | `8e1870ee…` | **Do not edit** |
| `tier_source_evidence_v1.py` | `6010c44b…` | **Do not edit** |
| `generate_transition_census.py` | UNAVAILABLE | Do not invent as authentic |

v2 adapters and `generate_transition_census_v2.py` are **new** code paths.
They must not be described as recovered authentic v0.

## Execution prohibitions (this phase)

- `NO_ORACLE`
- `NO_RTK_PREDICTION`
- `NO_BASELINE_EXECUTION`
- `NO_UNBLINDING`
- `NO_V0_REWRITE`
- `NO_CANDIDATE_LIST_MUTATION`
- `NO_TIER_A_WEAKENING`
- `NO_ATTESTATION_SUBSTITUTION_FOR_TIER_A`
- `NO_TIER_B_PROMOTION`
- `NO_FABRICATED_OVERLAY_CENSUS_IN_INTERFACE_FREEZE`
- `NO_CARDINALITY_TUNING`

## Interface-freeze deliverables (this pass)

1. This protocol document.
2. Generic adapter contract (Python ABC + docs).
3. `generate_transition_census_v2.py` skeleton + output schema docs.
4. Interface / reason-code / prohibition tests.
5. v0 compatibility harness (declared; may skip until adapters exist).
6. `RTK_EVAL_FREEZE.json` amendment entry pointing here.

**Next pass (after human review of this gate):** implement repository-specific
semantic mapping as needed, satisfy v0 compatibility, then process the five
frozen candidates under this protocol — still pre-oracle.
