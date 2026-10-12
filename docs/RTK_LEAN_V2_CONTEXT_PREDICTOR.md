# Lean v2 context-transport predictor — explicit refinement boundary

**Status:** executable **experimental RTK prediction algorithm**, implementing
a *conditional source/target context-equivalence rule*. This is **not** a
machine-checked soundness theorem, not native proof replay, not a calibrated
transport verdict, and not yet a full Lean proof-support extractor.

Implementation:
`experiments/rtk/lean_v2_context_predictor.py`.
Adversarial development tests:
`tests/test_rtk_lean_v2_context_predictor.py`.
Pre-oracle case freezing and commitments:
`experiments/rtk/lean_v2_preoracle.py`.

## 1. Mechanism

A `LeanTransportInput` binds one frozen historical claim/case to
two independently supplied typed `LeanContextManifest` objects (source
and target) and a source evidence/acceptance receipt reference.

The manifest records:

- Exact repository, Git revision, Lean file path and theorem symbol.
- Formal *statement* digest, separate from theorem display text.
- Native checker binary digest and checker configuration digest.
- Environment digest, relying-policy digest and trusted-axiom digest.
- Context-extractor digest.
- A named, directed proof-support graph with a claimed completeness flag.
- Dependency root identity and per-node typed semantic digests.

A deterministic graph walker recursively content-addresses only dependencies
reachable from declared proof roots. It detects missing nodes or cycles and
rejects duplicated identities. Extraneous unrelated nodes are excluded from
the closed support identity. Reordering graph serialization is not a
semantic change.

Transport **predicts VALID** only if the source evidence is recorded as
source-native `ACCEPTED` and `active`, support is claimed complete on both
revisions, source/target claim statements and all applicable checker,
environment, policy, axioms and extractor digests agree, and the complete
*declared* reachable support graph identity agrees.

A changed typed statement, semantic dependency, checker, runtime,
axiom context, extractor, relying policy, or revoked/expired source evidence
predicts `REVALIDATION_REQUIRED` when the declared contexts are otherwise
complete. Missing native source establishment, unknown evidence
admissibility, incomplete support, cycles, or missing dependencies predict
`UNRESOLVED`.

The predictor never emits `INVALID` without an independent same-subject
refutation. It creates *candidate* revalidation obligations without a
minimal-repair claim.

## 2. Central limitation

`support_claimed_complete=True` is **an unverified assertion by the
manifest producer**, not a proof that the graph includes every Lean
constant, inference assumption, instance, reduction dependency, attribute,
tactic dependency, imported axiom, and metaprogramming effect that could
alter proof elaboration or kernel checking.

A forged or mistakenly incomplete manifest could produce a false `VALID`
prediction. Content-addressed graph equality does not establish that the
graph faithfully represents Lean's checked proof dependencies.
An isolated digest or a Git commit SHA is not a native admissibility
witness. The source acceptance receipt is likewise supplied by a caller,
not authenticated by this predictor.

The verdict `VALID` is a **conditional prediction**, never an assertion
of transport soundness. Its output explicitly fixes

- `formal_soundness_established=false`;
- `native_oracle_consulted=false`;
- `external_manifest_authority_verified=false`.

Separate controls are necessary to establish authenticated Git history,
manifest authority, native source acceptance, complete sound support
extraction, signature validity, policy revocation, and target-native replay.

## 3. Relationship to OVK and RTK

This uses the *same conceptual architecture* as OVK's typed guarantee and
semantic evidence support: a durable claim, a revision-specific binding,
a trust policy, historical evidence, and a versioned support dependency
closure.

It is **not yet a proved refinement** of the abstract RTK
`T(q0,C0,E0;q1,C1,P)` calculus. Its support graph is newly typed for
Lean and does not import OVK's Protected Effect runtime/evidence decision.
The graph extractor, source-evidence admission and proof of equivalence
between these contexts and Lean's semantics remain explicit obligations.

In particular, the tests compare hand-constructed declarations and
content-addressed graphs. Passing them demonstrates internal algorithmic
consistency and rejection of specified mismatches; they do not measure
false reuse against an independent native oracle.

## 4. Experimental handoff

`make_prediction_bundle` consumes an exact ordered `FrozenCohort` and
`LeanTransportInput` per case, rejects changed case order and SUT
identity, and emits a `PredictionBundle` in the pre-oracle schema
introduced in draft #183.

The CLI takes separately prepared case and context input JSON and refuses
to overwrite existing prediction files. The required sequence is:

1. Independently review the exact source and target manifest producer.
2. Authenticate source/native acceptance and evidence subject identity.
3. Freeze the SUT and source/context adapter commit and target case
   selection rules **before target-native outcomes become available**.
4. Generate predictions and commit the sealed prediction receipt with the
   private nonce under the pre-oracle procedure.
5. Run independent native target certificate/term replay without access to
   predictor outputs.
6. Unblind once under independent chronology review; join results by
   exact source evidence, formal claim and target context.
7. Report case exclusions and `UNRESOLVED` outcomes separately; use
   repository-clustered inference and compare fixed baselines.

The successful external native replay development case in #182 is already
exposed and must remain in the *development* partition.
No repository from the 20-repository discovery snapshot in #183 has been
admitted as a confirmatory case, and none is evaluated here.

## 5. Required next engineering deliverable

Implement and externally review a *Lean-native manifest producer* that
extracts and authenticates dependencies from Lean's elaborated declarations
and checked proof expressions (including transitive constants and axiom
sets), with a documented account of elaborator, imported modules,
configuration and checker/version transport. A target-side native replay
adapter must be independently scoped to exactly the same claim and old
evidence bytes.

The producer should emit `UNRESOLVED` for unrepresentable proof
dependencies and should demonstrate adversarial disagreement cases,
including unchanged text with a changed import or inference instance.

Only once this abstraction has a justified soundness boundary is
`VALID` an engineering candidate for broader deployment. Until then,
all prediction outputs are research hypotheses, and production policy
authority is unchanged.
