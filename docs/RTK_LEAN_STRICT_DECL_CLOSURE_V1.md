# Strict bounded Lean declaration-reference graph

**Research-only, development case.** This experiment builds on draft
PR #193's `Lean.collectAxioms` axiom inventories and addresses its
documented silent failure mode: upstream `collectAxioms` ignores
unresolved declaration names while recursively scanning.

The new native walker enumerates the **precisely declared** relation
`Lean.ConstantInfo.getUsedConstantsAsSet` for a checked source
historical theorem, a target unproved goal placeholder, and an imported
`op` definition. It refuses missing constants and uncompleted
traversals, and preserves structural `Name` identities.

## Native execution

`experiments/rtk/lean_strict_decl_closure_v1.lean.txt`
uses the pinned Lean 4.14.0 `Environment.find?` API to verify that
**each** referenced constant is present *before scheduling it*.
It maintains a visited set and a queue to handle repeated references
and declaration cycles, bounded at **12,000 nodes and 180,000 direct
edges** per root. If either budget is exhausted, the probe fails and
does not issue a graph-completed result. The same missing-reference
predicate is also tested directly on a known absent name; a
zero-node-budget negative control must fail explicitly.

Each declaration node records its kind (definition, theorem, axiom,
opaque, inductive, constructor, recursor, quotient), module origin,
safety/partiality indicators, universe-parameter count, and full
direct-reference identities. Lean `Name` strings are treated as
human-readable labels; a recursive constructor AST distinguishes
`Name.str` and `Name.num` so collisions in textual rendering
do not silently merge declarations.

`experiments/rtk/lean_strict_decl_closure_v1.py` independently
validates the native report's node and edge budgets, schema, unique
structural identities, direct-reference total counts, complete reachability
from each root, closure of every reported edge over the reported nodes,
and imported module membership against prior installed-module inventories.
It explicitly rejects added bogus nodes, omitted dependencies,
contradictory sizes, duplicate identities, unsupported reliance flags,
and module origins outside the observed installation.

The dedicated workflow
`.github/workflows/rtk-lean-strict-declaration-closure-v1.yml`
runs source and target baseline scans **before** the prior target-only
axiom injection, then scans the changed target after recompiling the
same imported module with
`axiom rtkExternal (n : Nat) : Nat` and
`noncomputable def op (n : Nat) : Nat := rtkExternal n`.
The target is still a deliberately unproved goal placeholder and
the historical proof is never replayed against the target.

## Exact scope of completeness

The statement `complete_for_reported_reference_relation_under_budget`
means every declaration reachable through **the
`ConstantInfo.getUsedConstantsAsSet` relation as exposed by that
specific Lean 4.14.0 native Environment** was enumerated within
explicit budgets, and no referenced declaration was silently
ignored. The independent Python graph validator checks that stated
scope against the native JSON output.

It does **not** mean all proof-relevant Lean runtime and semantic
dependencies were captured. Even an exhaustive graph under this
relation may omit imported module implementation semantics, kernel
configuration, reducibility policy, generated recursor details,
unsafe/partiality behavior, proof irrelevance assumptions, compiler
metadata, axioms implicit in builtin rules, untrusted native runner
configuration and external relying policy. The walker is implemented
in the same checker installation and its output is not independently
attested as a faithful execution.

The changed target `.olean` file hash is recorded separately from
the **baseline** manifest. A new target-module binary cannot be
treated as if it were authenticated by the older manifest.

The known synthetic fixture is development-only. It does not support
an independent prospective false-reuse estimate. The conservative
result stays `REVALIDATION_REQUIRED`, historical applicability
`UNDETERMINED`, and `reliance_authorization=false`.
The native and Python guardrails do not constitute a formal
soundness theorem.

## Next acceptance conditions

1. Authenticate the exact source/target revisions, compiled module
   file bytes, native binary version, environment options and invoking
   runner, including the mutated target-module file.
2. Prove that the traversed graph relation covers precisely the
   kernel-relevant declaration types, bodies, axioms, inductive/
   recursor structure and universe semantics needed for the relying
   claim; or explicitly exclude unsupported constructs from authority.
3. Bind formal SUT predictions to signed pre-oracle evidence with
   externally governed holdout selection, then adjudicate separately
   by native checker and record false reuse versus unnecessary repair.

All results remain research-only and non-controlling.
