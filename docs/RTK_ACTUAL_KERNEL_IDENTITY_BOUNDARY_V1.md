# Actual Lean 4.14.0 kernel checking — exact-context preservation boundary (v1)

**Research status:** draft successor to #203. This document distinguishes a **proved actual-kernel congruence lemma** from the unresolved **environment-transport theorem**. It establishes no new production reliance permission.

## Kernel-grounded statement

In tagged Lean 4.14.0, `src/Lean/Environment.lean` defines the actual opaque, externally implemented operations:

- `Lean.Kernel.check (env : Environment) (lctx : LocalContext) (a : Expr) : Except KernelException Expr`
- `Lean.Kernel.isDefEq (env : Environment) (lctx : LocalContext) (a b : Expr) : Except KernelException Bool`
- `Lean.Kernel.whnf (env : Environment) (lctx : LocalContext) (a : Expr) : Except KernelException Expr`

The source file `experiments/rtk/lean_actual_kernel_context_identity_v1.lean.txt` states the actual-kernel acceptance predicate: the old expression is checked successfully and the returned inferred type is definitionally equal to the target claim. Lean checks four conditional theorems by equality substitution over **the full source and target Environment and LocalContext objects**: preservation of the kernel check result, definitional equality result, weak-head normalization result, and acceptance of the unchanged historical certificate.

These are genuine theorems referencing the actual Lean kernel API, not the first-order Nat evaluator defined in #199. **Their proofs are elementary congruence of opaque functions.** They are not a soundness or implementation-correctness proof of Lean's kernel. More importantly, no existing pre-oracle evidence here establishes their defining equality premises.

## Why the premise is not available

The native development experiment has **different environments by construction**: the source context includes a checked historical theorem, while the target context contains an unproved placeholder; their environment declarations cannot be treated as literally identical. In addition, the predecessor research identified cases where:

- Imported .olean module bytes match while a local helper declaration changes (#198).
- Native kernel header trust differs from the assumed zero-trust policy (#200).
- An imported axiom is accepted under trust zero yet has no derivation of its proposition (#202).
- Actual source/target expression constants agree with a syntactic visitor, but syntactic references alone do not establish full dependencies of kernel reductions (#203).

Consequently, exact imported module equality, native `collectAxioms` and `getUsedConstantsAsSet` records, direct `Expr.getUsedConstantsAsSet` parity, trust-zero replay, and absence of locally observed helper dependencies **do not imply `sourceEnv = targetEnv`**.

The actual-kernel congruence theorem therefore **does not apply to the current two-environment experiment**. Its value is to expose the true gap clearly and prevent a model-level theorem from being misrepresented as a Lean checker theorem.

## Required bridge for a useful transport theorem

The necessary research result is a *strictly weaker but semantically sufficient* context relation `KernelContextEquivalentFor(p, q, C0, C1)`, together with two separately justified statements:

1. **Operational preservation:** For the admitted Lean expression and declaration fragment, `KernelContextEquivalentFor` implies equal `Kernel.check` and `Kernel.isDefEq` outcomes on the original historical proof and exact target claim. This has not been proved.
2. **Extraction adequacy:** The authenticated pre-oracle facts actually imply that context relation. This also has not been proved. It involves relevant constant type/value semantics and opaque/inductive/reduction metadata, universe levels, declaration kinds, special quotient initialization, exact checker configuration, local context, source-certificate authenticity, and axiom/policy restrictions.

Proof of (1) needs a formal semantics or independently established refinement of the restricted kernel machinery. `Kernel.check` is opaque in Lean source, so merely invoking it in a theorem does not expose the implementation's recursion or permit a semantic-support induction. Proof of (2) needs a sound native extractor and an independently reviewed evidence/provenance contract, not merely matching observations made within the same runner.

Separately, a policy decision must determine whether a source theorem and its conditions are eligible for reliance, even in the event that kernel replay would accept it. The empirical study in #177 remains sealed and distinct from these proof obligations.

## Known kernel soundness defect in the pinned 4.14.0 executable

**Security qualification is blocked independently of the theorem above.** Lean's official [4.32.2 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.32.2/) disclose a kernel soundness defect that permits some axiom-free invalid proofs, including under zero-trust replay. The [August 2, 2026 security advisory](https://www.openwall.com/lists/oss-security/2026/08/02/1) identifies all Lean 4 versions through 4.31.0 as affected. This repository's source and target kernels are both **4.14.0**, inside that range.

This does not show the project's constructed equality/op proofs are false. It **does** invalidate an inference that `--trust=0` execution alone makes the old checker security-qualified for arbitrary adversarial historical proofs. The machine-readable research output explicitly records `legacy_pinned_kernel_version="4.14.0"`, `legacy_pinned_kernel_known_soundness_defect_unresolved=true`, `designated_kernel_security_qualified=false`, and `production_reliance_authorization=false`.

The [Lean 4.35.0 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.35.0/) describe new `lake check` and `lake check --paranoid` paths with isolated project builds, and bundled alternative checkers. A **separate patched-toolchain qualification lane** is now required by [issue #205](https://github.com/fraware/open-verification-kernel/issues/205). Rebuild all source and target artifacts under the patched version; do not replay old incompatible `.olean` files and pretend the checker version is unchanged. No evidence generated by draft #204 is a substitute for this migration or for the remaining semantic-transport theorem.

## Machine-checkable nonpromotion contract

The existing pre-oracle output explicitly states `full_kernel_environment_equivalence_proved=false`, `module_semantic_support_complete_proved=false`, `external_policy_and_provenance_authenticated=false` and `production_reliance_authorization=false`. This PR does not alter those flags, produce a `VALID` decision, or use a target replay result as a predictor input.

**Qualification:** compile the new Lean file using the pinned source Lean 4.14.0 binary with `--trust=0`; verify the exact-head native workflow, all six ordinary CI jobs, changed-file scope and draft/unmerged state. A green compilation establishes only the precise congruence theorems above.
