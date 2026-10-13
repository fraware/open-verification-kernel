# Cross-checking restricted Lean expression references against the native kernel AST

**Status:** draft development successor to #202. The reported references are verified syntactic occurrences, not proof of complete kernel semantic support or production applicability.

## Audit finding

The source and target certificate payloads are already checked by the strict structural-expression decoder. That decoder rejects unsupported `Expr` constructors. Nonetheless, the pre-oracle's own `_used_constant_ids` visitor previously assigned an empty dependency list to any unrecognized constructor. That behavior could become dangerous if a future code path invoked it without the upstream strict validation, or if the structural protocol expanded without updating the dependency visitor.

The visitor now explicitly handles the allowed terminal constructors (`bvar`, `sort`, `natVal`, `strVal`), descends into `const`, `app`, `lam`, `forallE` and `letE`, rejects projection expressions (as in #199), and **raises on any other tag**. Existing input-validation guarantees are retained; this is defense in depth, not a claim that an unsupported constructor could already pass the normal entry point.

## Independent native witness

The new `lean_native_expr_reference_probe_v1.lean.txt` uses Lean 4.14.0's `Expr.getUsedConstantsAsSet` on the actual source theorem's checked type and proof, the imported `op`'s type and value, and the target's **unproved** claim type and imported `op` fields. Its output encodes each `Name` structurally and states explicitly that kernel semantic support completeness is unproved and production reliance unauthorized.

A separate Python validator requires exactly one bounded record per checked source/target context, verifies root and declaration kinds, structural name identities, no target proof payload, no unsupported authority flags, and rejects duplicates. It then compares the native constant-name sets for all available expressions to an independently traversed copy of their serialized structural ASTs. The source proof/type AST must also match the exact historical source certificate, and the target type must match the unproved target claim. A disagreement raises a hard error before any conditional reuse decision.

Both source and target observations are gathered in the actual pinned Lean development workflow. In the zero-trust lane they run with `--trust=0` before the historical target-certificate oracle; the default-trust observations are also recorded but remain ineligible for positive reuse decisions. The axiom-injected negative fixture is checked independently and still abstains. Adversarial tests include extra native constants, altered proof sets, absent/malformed records, target proof contamination, unknown constructor types, and false kernel-completeness flags.

## Boundaries and next formal obligation

This establishes **observational agreement for syntactic constant occurrences** in the bounded exported expressions. It is not a theorem that `Expr.getUsedConstantsAsSet` contains every semantic dependency of Lean's kernel type-checking or definitional equality. Special kernel forms, opaque and inductive metadata, universes, relevance and environment configuration still need explicit treatment. The structural expression and native reference witness arise from the same overall Lean implementation and hosting context, so their agreement is not independent supply-chain attestation.

The project still needs a formally justified full-support contract for the admitted fragment, authenticated evidence and axiom/policy provenance, and prospective external adjudication under #177. No `VALID` authorization or merge is supported by this development evidence. #195 stays open.
