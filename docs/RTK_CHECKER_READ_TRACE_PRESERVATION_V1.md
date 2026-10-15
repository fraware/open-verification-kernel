# Adaptive checker read-trace locality — conditional preservation theorem

**Research-only successor to draft #214. 15 October 2026. No production evidence reuse authorization.**

## Why this milestone exists

PRs #212–#214 establish two different kinds of evidence. #212 proves locality and evaluator soundness for an explicitly defined finite evaluation trace; #214 records and independently cross-checks a *static* graph of safe definition references extracted from the checked Lean 4.35 environment. The missing inference is that the actual verification algorithm performs no semantically relevant environment/configuration lookups beyond that graph.

A checked reference graph is insufficient for this inference. A checker can adapt its future queries based on the values of previous queries, test for the **absence** of a declaration, consult the local environment or a checker option, or obtain reduction/inductive data not represented by direct definition bodies. A preexisting positive-name dependency graph does not necessarily capture those effects.

This PR formalizes a stronger, algorithmic proof principle that states precisely what a *complete* dynamic read certificate would justify. It is not yet instrumenting or verifying the actual kernel.

## Formal statement

`experiments/rtk/lean_checker_read_trace_preservation_v1.lean.txt` defines:

- `Key` with separate namespaces for declaration and checker-option observations.
- `Context : Key → Option Nat` — a deliberately abstract lookup environment.
- `Program α` — a finite, adaptive checker decision tree with `result` and `read key (Option Nat → Program α)` steps. Its program object is fixed between source and target.
- `Executes env program trace outcome` — an inductive judgment checking the *exact* value returned by every read, recursively validating the continuation chosen by that value. A missing declaration appears as `none`.
- `Preserved target trace` — every recorded source read, including negative/missing lookups, returns the same observation under the target context.

The main theorem `historical_execution_preserved` proves by induction over a validated historical execution:

```
Executes(source, program, historicalTrace, outcome)
AND forall (key, observed) in historicalTrace,
       target[key] = observed
-------------------------------------------------
Executes(target, program, historicalTrace, outcome)
```

The result transports a *specific execution* and its *specific outcome* without assuming source and target environments are identical everywhere. The program may select additional reads based on earlier observations; the induction shows the same branch and subsequent trace still apply under preserved observations. No case assumes that a missing lookup may be omitted.

The development witness demonstrates that checking for a missing `forbidden` declaration leads to an accepted Boolean conclusion in the empty context, while adding that declaration changes the result. The historical read `(forbidden, none)` is not preserved. Another witness treats a checker safety option as an explicit input dependency.

This is a proof of a **sufficient** condition for execution preservation, *not* a proof that each read is individually necessary. Results might remain identical despite changed reads; claiming minimality from the trace would be false.

## Exact trust / refinement obligation

The theorem only applies to a real verifier if all of the following are independently established:

1. **Program correspondence.** A fixed `Program` describes the actual checker algorithm, or an instrumented production checker is proved observationally equivalent to that program for an exact admitted source/target fragment. Neither such result has been established for Lean 4.35.
2. **Complete read mediation.** Every environment/configuration-dependent branch influencing the actual verdict uses an instrumented `read`. This includes successful and **failed** declaration lookups, local context, safety policy, universe metadata, reduction/recursor data, checker options and fuel/time/exception behavior as applicable. A partial trace invalidates the premise.
3. **Trace authenticity.** A source execution is validated against the exact source program, checked environment, certificate, claim and policy. Merely hashing caller-supplied trace JSON does not prove `Executes`.
4. **Target comparison.** Each recorded observation is reobtained from the actual target checker context, with authenticated environment/module/revision binding. The recorded `Option Nat` values are an abstraction; actual checker records need typed identity for complete `ConstantInfo`, built-ins, and relevant state, not an unqualified hash alone.
5. **Security and relying policy.** Checker version/security qualification, trusted axioms, revocation, evidence issuer and relying authority are separate. Even a theorem about a checker's computed answer does not authenticate input evidence or authorize reliance.

## Concrete Lean4Lean audit

The contemporaneous [Lean-for-Lean](https://github.com/digama0/lean4lean) checkout examined for this work names **Lean 4.33.0-rc2** in `lean-toolchain`, while this project's native experiment is pinned to **Lean 4.35.0**. No cross-version correspondence theorem exists here.

- `Lean4Lean/TypeChecker.lean` defines `TypeChecker.Context` with `env`, `lctx`, `safety`, `eagerReduce`, `lparams` and `fuel`. `inferConstant` reads `tc.env.get name`, consults `levelParams`, `isUnsafe`, `safety` and `partial` policy. Other branches read inductive and constructor declarations, local variable contexts, and reduction settings.
- `Lean4Lean/Inductive/Reduce.lean` directly reads environment declarations, including inductive, constructor and recursor metadata through `env.find?`.
- `Lean4Lean/Environment.lean` adds declarations using typechecking and conversion checks; a theorem check invokes `TypeChecker.checkType` followed by `isDefEq` against the claim.
- The upstream project's own `README.md` says its implementation was derived from the C++ kernel and is not independent in that sense. `divergences.md` details discrepancies (including primitives, projections, recursion/fuel, and level comparison). Its verification relation in `Lean4Lean/Verify/Environment/Basic.lean` has an unimplemented inductive-environment case, explicitly noted there. These limitations preclude a blanket production-kernel soundness inference.

Thus Lean4Lean is useful for identifying and eventually mediating the real checker read surface; importing its implementation without version alignment or a proven correspondence would be invalid.

## Current outcome and next acceptance gate

The Lean 4.35 pinned source workflow now builds the separate `RTKCheckerReadTrace` module and checks it alongside the historical source under `lake check --paranoid`. The existing #214 native historical-proof predictions and target oracle remain independent and unchanged; the new abstract theorem is *not* used to classify actual Lean evidence.

Once exact-head qualification passes, the contribution is an auditable **conditional noninterference theorem**, with negative-lookup and checker-option controls. It must never be relabeled an actual-kernel locality proof.

**Next empirical/methodological gate:** build an instrumented, pinned checker entry point whose read events cover one real historical certificate fragment, including negative lookups and all relevant metadata. Define a checkable relation connecting raw emitted events to the interpreter's `Executes` judgment; show a constructible counterexample from an omitted read, and preserve oracle-blind target replay. If the checker cannot be instrumented comprehensively, document that as a NO-GO for sound replay-free reuse. A future minimal repair plan needs an explicit sound recheck-operation set and cost model; neither follows from this theorem.

All related PRs remain research-only, stacked, draft and unmerged. Issues #195 (kernel support), #177 (prospective independent evaluation), and #205 (security/relying qualification) remain open.
