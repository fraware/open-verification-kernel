# Transitive historical-evidence support — bounded preservation theorem

**15 October 2026. Status: development only. No production VALID.**

This successor to [PR #211](https://github.com/fraware/open-verification-kernel/pull/211) addresses an important gap between *matching an immediately referenced declaration* and *preserving all the transitive lookups a previous result depended on*. It contributes a genuinely inductive preservation argument **over a separately defined finite evidence-evaluation calculus**, while explicitly leaving actual Lean kernel refinement unresolved under [issue #195](https://github.com/fraware/open-verification-kernel/issues/195).

## Precise claim

The model's `Term` constructors are a natural-number literal, named constant reference, and addition. An `Environment` maps names to optional terms. `Eval env term value` is an inductively constructed **finite derivation** recording successful evaluation, including the transitive unfolding of referenced constant bodies. The inductive proof object is computational data in `Type`.

`Eval.support` recursively extracts exactly the declaration names used by that particular derivation. It descends through the body of every unfolded declaration. It is **historical-proof-specific**: a different derivation, or a changed environment with different unfolding, may have a different support.

The formal preservation obligation states:

```
historical : Eval source term value
agree : forall name in historical.support,
          source[name] = target[name]
------------------------------------------------
Eval target term value
```

The theorem `transport` is proved by structural induction on `historical`. In the constant case, agreement preserves the exact looked-up body, while the inductive hypothesis transports the nested derivation. In the addition case, the two independent historical subderivations are transported. This is strictly weaker than whole-environment identity: unrelated names can change freely.

The proof is a **sound locality theorem for the model's explicit evaluation relation**, not a tautological claim that the two entire environments are equal. It neither proves optimality of a revalidation frontier nor quantifies the cost of repairing invalid evidence.

## Adversarial model witness

Two model environments share exactly the same immediate `op` body, `op -> base`; however, `base` changes from 0 to 1. The historical source evaluation of `op` yields 0 and the target evaluation yields 1. The historical evaluation support includes both `op` and `base`. Thus an immediate-declaration-only equality policy would omit a necessary transitive condition in this expanded fragment.

This is a model-level **boundary witness**, not a false-positive observation in #211's actual native Lean experiment. PR #211 intentionally rejects unknown additional constant names in `op` and therefore does not admit this extended case as a candidate.

## Required bridge before making an actual Lean kernel transport claim

1. **Native correspondence:** Define an explicit embedding from the accepted Lean `Expr`/claim/certificate fragment into this model, or a richer small kernel that covers beta/delta/zeta reduction, dependent function types, universes, Eq constructors, recursors and proof irrelevance as actually needed. No such embedding is proved here.
2. **Support extraction:** Prove or independently audit a complete, trusted extractor of the kernel-relevant declaration support for that fragment. The current model's `support` is derived from a given historical derivation and is complete *by construction* only relative to that derivation.
3. **Authentic environments:** Establish that recorded source/target declaration identities refer to precisely the kernel environments loaded by each checker. A content hash or single `op` AST observation does not independently authenticate the entire kernel support.
4. **Original certificate:** Keep the target historical-certificate replay oracle entirely separate from replay-free applicability prediction. Fresh target proof success does not establish old-proof applicability.
5. **Trust and relying policy:** Qualify the patched kernel and relevant independent checkers for the intended scope, declared axioms, issuer/provenance, revocation, and relying authority. All existing `VALID` gates remain closed.
6. **Repair:** On a versioned dependency/evidence graph, compute revalidation obligations with a proven soundness criterion; only claim minimality under an explicit repair operation set and cost model. Evaluate unnecessary work and false reuse prospectively under #177.

The exact-head patched Lean workflow builds this source file as a new Lake library alongside the historical source theorem and checks the project with `lake check --paranoid`. That would establish kernel acceptance of the formal model proof **once the workflow completes successfully**; it is not an external proof of correctness of Lean's opaque `Kernel.check` over changed target contexts.

## North Star

The long-term goal is a maintained, machine-checkable account of which historical conclusions remain licensed under change and the smallest justified work that restores them. This model is one narrow step in specifying a support-based applicability condition. A general software evidence graph, new universal DSL or simply more green verifier runs would not resolve the scientifically central question of support adequacy and transport.

**No release, merge, or production evidence authority changes are authorized by this draft.**
