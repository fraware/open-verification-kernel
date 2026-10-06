# Source Universe Expansion Protocol v1

Status: methods freeze. No oracle labeling. No RTK prediction execution.

## Purpose

Define how additional source repositories may be admitted into the RTK sealed
evaluation **source universe** after source-universe-v0 is recorded, and before
any oracle work begins.

## Non-goals

- Does not authorize oracle construction, RTK prediction, baseline execution, or
  unblinding.
- Does not rewrite source-universe-v0.
- Does not treat the 20-transition feasibility gate as a scientific validity
  criterion; it is a pre-oracle feasibility rule only.

## Source-universe-v0 (immutable identity)

source-universe-v0 is permanently recorded as the pair of public repositories
and cutoffs below. OVK must never rewrite v0 identities.

| Repository | URL | Cutoff SHA | History rule |
|---|---|---|---|
| CertifyEdge | https://github.com/fraware/CertifyEdge | `6ef02d54c4697886b20577f10eec683861475db2` | FIRST_PARENT |
| pcs-core | https://github.com/SentinelOps-CI/pcs-core | `9c971f5f9da8a424924dd8f48d6a3b71a1009e1b` | FIRST_PARENT |

External sealed digests associated with a prior private evaluation of this v0
identity are recorded in `EXTERNAL_SEALED_REFERENCES.v0.json` with provenance
`EXTERNAL_REPORT_UNVERIFIED_ON_OVK`. Local OVK workflows must not claim those
digests as reproduced unless identical artifacts are materialized here.

## Eligibility (source-side only)

A candidate repository is expansion-eligible only if all hold:

1. Public, cloneable history at a declared cutoff SHA.
2. FIRST_PARENT traversal yields well-defined transitions.
3. Eligibility is computable from repository state alone (paths, timestamps,
   declared artifact classes). It must not depend on RTK output or oracle labels.
4. The repository is listed in `SOURCE_REPOSITORY_CANDIDATES.v1.json` **before**
   any added-repo content inspection beyond identity metadata (URL, default
   branch, cutoff SHA, license if published).

## Freeze-before-inspection

The ordered candidate list is frozen in
`SOURCE_REPOSITORY_CANDIDATES.v1.json` before inspecting added-repo trees for
case content. Reordering, insertion, or deletion after inspection begins
requires a new candidates file version and an amendment entry in
`RTK_EVAL_FREEZE.json`.

## Expansion stop rule

If the ordered candidate list is exhausted and the pre-oracle feasibility gate
(target: at least 20 eligible transitions under the frozen census procedure)
is still unmet:

**STOP EXPANSION.**

Do not search indefinitely for further repositories. Do not run the oracle in
this phase. Record `expansion_status: STOPPED_CANDIDATE_LIST_EXHAUSTED` in the
freeze amendment history.

## Admission procedure (post-freeze, pre-oracle)

For each candidate in order:

1. Record clone URL and cutoff SHA.
2. Enumerate FIRST_PARENT transitions up to cutoff.
3. Apply frozen source-side eligibility rules only.
4. Append admitted transitions to an **expansion overlay** census; never mutate
   source-universe-v0 artifacts.
5. Stop early if the feasibility gate is met.
6. If the list ends without meeting the gate, stop expansion permanently for
   this evaluation version.

## Relationship to Tier A / Tier B

Expansion only affects the source transition pool. Scoring tiers remain:

- Tier A = `REPLAY_VERIFIED` (primary scoring set).
- Tier B v1 = `COMMITTED_NATIVE_ATTESTATION` (secondary; do not inflate Tier A).
- Tier B v0 is excluded from scoring.

Tier labels are assigned only after source-evidence materialization exists on
OVK. Until then, tier counts remain `NOT_LOCALLY_PRODUCED`.
