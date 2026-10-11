# Prospective v2 adjudication normalizer — development artifact

**Status:** development-only. Does not modify frozen v0/v1 selection records,
execute any native verifier, score any SUT, or establish independent evidence.
No confirmatory sample, false-reuse measurement, or proof claim follows from
passing the tests in this directory.

Implementation: `experiments/rtk/adjudication_v2.py`.
Tests: `tests/test_rtk_adjudication_v2.py`.
Research protocol: `docs/RTK_ORACLE_IDENTIFIABILITY.md`.

## Trust partition

A **source-side adapter** identifies `E0`, `q1`, and `C1` before access
to target outcomes. A **native adjudicator** independently produces exact
claim/context-bound witness artifacts for old-evidence applicability and
target-claim truth. The **normalizer implemented here** accepts references
to those artifacts and enforces the two-axis decision table. A **scorer** must
remain separate and read SUT predictions only after they were sealed.

The normalizer treats witness hashes, checker identities, and invocation
hashes as *unverified claims*. It cannot tell whether an artifact exists,
its SHA-256 was computed from real bytes, whether the checker ran, whether
the native verifier is sound, or whether a native observation truly concerns
the same typed claim. It checks only structural consistency, not oracle
independence or semantic sufficiency.

## Label rules

- Old evidence **ADMISSIBLE** with independently established or unrun target
  truth gives `VALID`, conditional on an independent replay/continuity witness
  providing sufficient authority for the exact historical evidence.
- Old evidence **INADMISSIBLE** without a same-subject target refutation gives
  `REVALIDATION_REQUIRED`.
- A properly scoped **REFUTED** target claim gives `INVALID`, unless a
  purported old-evidence admissibility witness conflicts, in which case
  `UNRESOLVED` and an authority-conflict reason are emitted.
- **UNDETERMINED** old-evidence applicability, with no authoritative target
  refutation, gives `UNRESOLVED` even if fresh target verification succeeds.
- Operational failure gives `UNRESOLVED` without laundering the outcome
  into revalidation or invalidity.

## Development test matrix

Tests enumerate the complete independent-axis decision table and negative
controls for missing basis, inadmissible witness families, wrong source
evidence digest, target claim/context mismatch, operational failure,
unknown applicability despite fresh target PASS, contradictory authorities,
unexpected SUT prediction fields, and model-copy validation bypasses.

## Prospective admission conditions

A v2 confirmatory protocol must be separately preregistered **before**
evaluating target-side outcomes. It must include:

1. Exact, content-addressed source claims and prior evidence bytes.
2. The governing versioned protocol, source/target repositories, adapter
   families, implementation SHAs, checker invocations and relying policies.
3. An independent certificate-replay or claim-specific applicability basis,
   with executable positive and negative development controls.
4. A verified artifact store that recomputes every claimed digest and
   authenticates checker output and historical provenance.
5. Prediction sealing and oracle blinding until the final single unblind.
6. An exclusion/abstention register and repository-cluster-level reporting.
7. No post-outcome changes to case qualification, oracle families or labels.

The present normalizer satisfies only the **syntactic label-derivation** part
of that gate. Native admissibility adapters remain an open scientific and
engineering task. No source-discovery or corpus-qualification status changes.
