# Lean-native dependency extraction: implementation contract

**Status:** source-grounded design obligation, not an implemented or verified
extractor. This document identifies concrete upstream Lean 4.14.0 API entry
points, and the independence constraints for a successor engineering task.
The existing context-transport predictor does **not** call these APIs.

## Pinned Lean 4.14 source evidence

Upstream repository: `leanprover/lean4`, tag `v4.14.0`, commit
`410fab7284703f41660ca2454218dcca9b2ec896`.

- `src/Lean/Util/FoldConsts.lean`, Git blob
  `cd1608bf652e737a3c679a719a6fd9082f7934b5`.
  `Expr.getUsedConstants` traverses expression nodes to enumerate
  referenced global constant names, and
  `ConstantInfo.getUsedConstantsAsSet` combines type and value
  references for a declaration. Its source uses a fold of `Expr.const`
  nodes. Constant names alone do not encode a proof of transport.
- `src/Lean/Util/CollectAxioms.lean`, Git blob
  `fd688d0b5868150033f8a2d3632438ff42825fde`.
  `Lean.collectAxioms` follows transitive type/value references from
  one constant, recognizing axioms and ordinary declaration kinds.
  The exposed `Lean.CollectAxioms.collect` recursion is a concrete
  model for traversing the trusted constant environment.
- `src/Lean/Declaration.lean`, Git blob
  `b764111ddaa995e9a0cd7d49824de83ce100d9f3`.
  The `ConstantInfo` variant constructors distinguish theorems,
  definitions, opaque definitions, axioms, inductives, constructors
  and recursors, and expose types and values where supported.
  This is stronger evidence than matching theorem source strings.

These source records establish available code entry points at a pinned
version. They **do not** establish that our extraction algorithm is sound,
that `getUsedConstants` is an exhaustive applicability dependency model,
or that target context hashes represent kernel semantics.

## Proposed source-side producer

Given a *source-native accepted* historical theorem and its exact source
environment, an independently tested, version-pinned Lean program shall:

1. Identify exactly one typed `ConstantInfo.thmInfo` for the source
   theorem. Reject ambiguity, unresolved constants, unexpected declaration
   kinds, and unavailable kernel expressions.
2. Traverse referenced constants in its checked type and checked proof
   expression using `Expr.getUsedConstants`; recursively follow both
   types and values of referenced declarations, respecting declaration
   kind, axioms, universe-level parameters, expression structure,
   opaque/reducibility behavior, and imported constants.
3. Record the exact checked theorem expression identity, proof expression
   identity, transitive dependency names/identities, axiom set and
   checker/version/configuration identity.
4. Use a specified **semantic serialization** of expressions and
   declaration values to compute stable content digests. Pretty-printed
   Lean terms or unstable runtime pointers do not meet this requirement.
5. Retain authentic source-native execution bytes, the actual historical
   proof digest, exact source commit and file identities, tool binary
   digest, and explicit relying-policy/revocation state.
6. State the exact supported fragment and any unresolved constructs.
   If support extraction is incomplete or non-deterministic, set the
   manifest completeness flag to **false**.
7. Validate positive and negative controls under pinned Lean:
   irrelevant revisions, changed transitive definitions, changed
   axioms, changed elaboration/instance context, checker drift, opaque
   definitions, and actual historical proof replay disagreement.

## Target-side independence

The pre-oracle predictor may inspect selected **target source metadata**
under a frozen rule, yet it must have no access to a target native
verification PASS/FAIL or to source evidence replay results. Producing
a target manifest by *checking the historical proof under the target
Lean kernel* would be oracle leakage.

The target context extraction process must separately document whether
its operations amount to new target-native claim verification. If they
do, either the relevant cases are development-only or the model/oracle
isolation design needs an independently reviewed protocol revision.
No label can be called an independent oracle if it is algebraically
determined by the predictor's decisive support hash.

A sound completeness statement must bridge:
`same_transitive_support_hashes` plus policy/checker equivalence to
`historical_proof_native_admissibility` for the exact claim fragment.
The generic Lean API references above do not supply that theorem.

## Output/transport compatibility

The producer is to populate
`LeanContextManifest` and `LeanHistoricalEvidence` from
`experiments/rtk/lean_v2_context_predictor.py`, binding every record
to a `FrozenLeanCase` in
`experiments/rtk/lean_v2_preoracle.py`.

Until this native producer is implemented, tested and subjected to an
independent completeness review, caller-supplied manifests remain
**assertions**. The predictor's conditional `VALID` output remains
non-controlling research information, and the selected holdout
must remain unopened.
