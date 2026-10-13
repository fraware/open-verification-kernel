# Local declaration scope for Lean pre-oracle byte identity (development v1)

**Status:** draft research hardening stacked above #197. This is a **soundness boundary correction**, not completion of the general Lean support-completeness obligation (#195).

## Gap closed at the predicate boundary

The previous strict byte-identity predicate compares every `.olean` file named by the target's loaded-import inventory. Lean's kernel environment includes **local declarations** that are absent from those imported module files. Equality of all imported bytes does not constrain the types or values of a local definition referenced by the historical certificate or target proposition.

A native development counterexample uses two separately installed pinned Lean 4.14.0 installations, with **identical imported module bytes**, and the same structurally checked target type:

- Source: `def rtkLocal (n : Nat) := n`, followed by the source theorem `rtkLocal n = n` established with `Eq.refl n`.
- Target: `def rtkLocal (n : Nat) := 0 + n`, with only an **unproved** target placeholder having the same structural proposition.
- The original proof source `Eq.refl n` does not establish this claim in the changed target context, even though no imported module differs.

The workflow checks the source theorem in the actual source Lean installation, checks the target placeholder in the target installation, compares native structural theorem-type ASTs, verifies all source-recorded imported `.olean` hashes equal their current target counterparts, and validates native bounded declaration-reference graphs on both sides. It separately checks that the same historical proof *source expression* fails under the target. **This negative control does not yet replay a serialized proof AST for the local case, and does not constitute a proof of all Lean environment incompatibilities.**

## New admissibility gate

Before producing a conditional candidate, the pre-oracle predictor now requires both native bounded reference-closure logs:

- source historical theorem, whose type and checked proof are structurally inspected;
- current target unproved claim, extracted under the actual candidate target module environment.

For both roots, it checks the native `ConstantInfo.getUsedConstantsAsSet` dependency graphs using the existing strict graph validator, rejecting missing names, invalid edges, budget failure, incompatible root/declaration kinds, and references outside the natively inventoried imported module set.

**Only the claim/theorem root itself is permitted to have `module == "LOCAL"`.** The imported `op` definition must be in `RTKSemanticSupport`. Any other reachable local declaration produces `UNRESOLVED` with `unaccounted_local_declaration_dependency`, even if all imported bytes are identical. Both the serialized historical proof and target claim ASTs have their syntactically referenced constants checked against the reported native root closure; the supported fragment explicitly requires reference to imported `op`.

The output's `native_import_only_scope_checked` records this gate, while `native_reference_relation_semantic_completeness_proved` remains false.

The gate is deliberately restrictive and will abstain for many legitimate Lean files with local helper definitions. That is the correct behavior until local declarations receive independent semantic fingerprints and their binding to the certificate can be established.

## What this proves and does not prove

It establishes **an executable exclusion of one previously untracked attack surface** for the specified native reference relation and fixture. It does not prove:

- that `getUsedConstantsAsSet` includes all kernel-relevant influences;
- equivalence of every part of the kernel environment, such as `quotInit`, local declarations outside this declared reference relation, special built-ins, or checker options;
- authenticity of raw native logs or trusted issuer identity;
- axiom policy, certificate revocation/expiration, exact reconstruction of the runtime state from `.olean` bytes, or semantic adequacy of the theorem;
- equivalence of the actual Lean kernel under different versions;
- machine-checked general soundness, confirmatory predictive performance, or reuse authorization.

The earlier development fixture remains separate from the prospective cohort in #177. Do not reuse its outcomes as held-out evidence and do not promote `CONDITIONAL_IDENTITY_CANDIDATE` to `VALID`.

## Next gates

Formalize an explicit restricted-environment state including **all local declarations or their provably safe exclusion**, native kernel configuration and trusted axiom policy. Prove or independently justify a preservation relation for native proof checking in that state; then preregister blind external examples and adjudicate exact historical certificates under issue #177. Preserve the research-branch sequence and non-controlling output contract.
