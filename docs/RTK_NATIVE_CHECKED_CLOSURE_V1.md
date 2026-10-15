# Checked declaration graph closure — native Lean 4.35 development v1

**Research-only.** Success means that a finite, explicitly restricted graph is closed with respect to *the constant-reference relation recorded from a native Lean environment*. It does **not** mean that it contains every condition governing the Lean kernel's acceptance of a historical proof, nor that past evidence is authorized for relying use.

## Research question and relation

PR #213 directly observed two named declarations, `op` and `base`. This successor removes the manually enumerated dependency list in the observer. Native Lean traverses the checked source or target environment beginning with the actual theorem/goal's constant references; each non-core referenced declaration must resolve to a **safe definition**, whose type, value, universe parameter list, reducibility hint and direct constant references are recorded. The traversal follows both type and value references until a bounded fixed point or an explicit failure.

For this initial fragment, `Nat`, `Nat.succ`, `Eq`, and `Eq.refl` are a named **trusted core frontier**. They are *not checked for semantic equivalence* by this graph; their meaning and the patched checker context remain external assumptions. A real product would need authenticated core/environment identities and an adequate model of the kernel's built-ins.

The second validator, implemented independently in Python, reconstructs direct references from each emitted strict expression AST, checks exact declared-node reachability, rejects missing/extra nodes, duplicate or malformed edges, cycles, unsafe/partial/opaque/axiom/inductive/recursor declarations outside the admitted frontier, universe parameters, unknown expression forms and unsupported metadata. Its closure property is explicitly **relative to the inspected expression syntax**. It does not grant a native kernel-support completeness property.

The source manifest is bound to the original serialized source claim and proof expression, independently rechecked under pinned Lean 4.35. The target manifest is bound to an unproved claim observation. A target's historical proof is unavailable until both manifests and pre-oracle decisions are committed. Only the old source proof is used for target adjudication.

## Three frozen, exposed development controls

The original source contains a three-level import chain:

```lean
def leaf (n : Nat) : Nat := n
def base (n : Nat) : Nat := leaf n
def op (n : Nat) : Nat := base n
theorem historical_claim (n : Nat) : op n = n := Eq.refl n
```

| Target change | Expected graph comparison | Expected native old-proof replay |
| --- | --- | --- |
| Independently rebuild identical three-level chain | `CONDITIONAL_CLOSED_REFERENCE_CANDIDATE` | `ADMISSIBLE` |
| Change only `leaf n := Nat.succ n`, preserve `base` and `op` | `REVALIDATION_REQUIRED`, differing node `leaf` | `INADMISSIBLE` |
| Add unrelated definition outside reachable chain | `CONDITIONAL_CLOSED_REFERENCE_CANDIDATE` | `ADMISSIBLE` |

These expected labels are development controls, **not measured results until exact-head CI and native replay succeed**. New cases in this branch cannot be used as confirmatory cases under #177.

## Strict interpretation

The native observation is produced by Lean 4.35.0 and contains checked declaration metadata and strict ASTs, but the native constant collector (`Expr.getUsedConstantsAsSet`) is implemented in opaque/runtime code and the current visitor does not establish its own correctness as a theorem. A Python cross-check against a second AST traversal is an important consistency test, **not a mathematical proof of semantic sufficiency**.

Lean kernel conversion may involve opaque declarations, recursor/inductive metadata, builtin computation, universe constraints, proof irrelevance, and environmental configuration beyond this restricted named-definition graph. The code rejects constructs outside its local syntax/metadata assumptions, and still relies on an explicit trusted core frontier. Independent environment issuance, revocation, witness signing, and relying policy remain unestablished.

A `CONDITIONAL_CLOSED_REFERENCE_CANDIDATE` indicates **observed graph compatibility under the stated limits**, never `VALID`. A graph change triggers a conservative revalidation request, without claiming the old evidence must fail. Unknown or malformed evidence aborts, and absence of support-completeness proof bars production reuse.

This advances the North Star only insofar as it exposes a concrete, inspectable support relation and its residual trusted boundary. The next scientific obligations remain (i) a preservation theorem for an actual checker-relevant fragment that subsumes the observed relation, (ii) authenticated source/target evidence and authorization, (iii) prospective independent oracle evaluation, and (iv) sound and appropriately minimal repair under an explicit cost model. The related machine-checked trace calculus (#212) is **not** a proven refinement of Lean's actual kernel.
