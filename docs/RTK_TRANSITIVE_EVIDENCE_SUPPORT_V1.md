# Transitive historical-evidence support — bounded preservation theorem

**15 October 2026. Status: development only. No production VALID.**

This successor to [PR #211](https://github.com/fraware/open-verification-kernel/pull/211) addresses an important gap between *matching an immediately referenced declaration* and *preserving all the transitive lookups a previous result depended on*. It contributes a genuinely inductive preservation argument **over a separately defined finite evidence-evaluation calculus**, while explicitly leaving actual Lean kernel refinement unresolved under [issue #195](https://github.com/fraware/open-verification-kernel/issues/195).

## Precise claim

The model's `Term` constructors are a natural-number literal, named constant reference, and addition. An `Environment` maps names to optional terms. A `Trace` is an explicit finite *data artifact* describing literal evaluation, addition, and transitive unfolding, including the exact expected body at every referenced name. `Trace.valid env` is a proposition requiring all recorded lookups and subtraces to agree with the environment. `Trace.term` and `Trace.value` project the claimed term and result.

`Trace.support` recursively extracts the declaration names unfolded by that particular trace. It includes nested transitive dependencies. It is **historical-evidence-specific**: a different trace, or a changed environment with different unfolding, may have a different support.

The formal preservation obligation states:

```
historical.valid source
agree : forall name in historical.support,
          source[name] = target[name]
------------------------------------------------
historical.valid target
```

The theorem `valid_transport` is proved by structural induction on the explicit historical `Trace` data. In the constant case, agreement preserves the exact looked-up body, while the inductive hypothesis transports the nested trace's validity. In the addition case, the two independent historical subtraces are transported. This is strictly weaker than whole-environment identity: unrelated names can change freely.

The proof is a **sound locality theorem for the model's explicit trace validity relation**, not a tautological claim that the two entire environments are equal. A second inductive relation, `Evaluates env term value`, independently defines literal, addition, and constant-unfolding evaluation **without using `Trace.valid` or `Trace.support`**. The theorem `trace_sound` establishes that every valid trace is a correct evaluation under that relation. Composing both results, `certified_result_transport` establishes that a source-valid historical trace with all transitive lookups preserved justifies the **same specified evaluation result in the target model**. This is a model-level soundness statement with an explicit semantic target; it neither proves optimality of a revalidation frontier nor quantifies the cost of repairing invalid evidence.

## Adversarial model witness

Two model environments share exactly the same immediate `op` body, `op -> base`; however, `base` changes from 0 to 1. The historical source evaluation of `op` yields 0 and the target evaluation yields 1. The historical evaluation support includes both `op` and `base`. Thus an immediate-declaration-only equality policy would omit a necessary transitive condition in this expanded fragment.

The source's historical trace is valid for the source environment but invalid for the target environment; a separate target trace records the changed result. This is a model-level **boundary witness**, not a false-positive observation in #211's actual native Lean experiment. PR #211 intentionally rejects unknown additional constant names in `op` and therefore does not admit this extended case as a candidate.

## Required bridge before making an actual Lean kernel transport claim

1. **Native correspondence:** Define an explicit embedding from the accepted Lean `Expr`/claim/certificate fragment into this model, or a richer small kernel that covers beta/delta/zeta reduction, dependent function types, universes, Eq constructors, recursors and proof irrelevance as actually needed. No such embedding is proved here.
2. **Support extraction:** Prove or independently audit a complete, trusted extractor of the kernel-relevant declaration support for that fragment. The current model's `support` is computed from a given historical trace and is complete *by construction* only relative to that trace, contingent on the separate proof that it is valid for the source environment.
3. **Authentic environments:** Establish that recorded source/target declaration identities refer to precisely the kernel environments loaded by each checker. A content hash or single `op` AST observation does not independently authenticate the entire kernel support.
4. **Original certificate:** Keep the target historical-certificate replay oracle entirely separate from replay-free applicability prediction. Fresh target proof success does not establish old-proof applicability.
5. **Trust and relying policy:** Qualify the patched kernel and relevant independent checkers for the intended scope, declared axioms, issuer/provenance, revocation, and relying authority. All existing `VALID` gates remain closed.
6. **Repair:** On a versioned dependency/evidence graph, compute revalidation obligations with a proven soundness criterion; only claim minimality under an explicit repair operation set and cost model. Evaluate unnecessary work and false reuse prospectively under #177.

The exact-head patched Lean workflow builds this source file as a new Lake library alongside the historical source theorem and checks the project with `lake check --paranoid`. The earlier trace-validity theorem passed at commit `d0f172ccd5e568d8ec6a27dd2bded077538147f5` (native run 38773103664). The newly added evaluator-soundness and composed-transport theorems have a **new unqualified head** until their own exact-head native workflow succeeds. No kernel checker validation here is an external proof of correctness of Lean's opaque `Kernel.check` over changed target contexts.

## North Star

The long-term goal is a maintained, machine-checkable account of which historical conclusions remain licensed under change and the smallest justified work that restores them. This model is one narrow step in specifying a support-based applicability condition. A general software evidence graph, new universal DSL or simply more green verifier runs would not resolve the scientifically central question of support adequacy and transport.

**No release, merge, or production evidence authority changes are authorized by this draft.**
