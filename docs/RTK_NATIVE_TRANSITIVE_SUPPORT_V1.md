# Native Lean 4.35 transitive historical-certificate support — development v1

**Status:** research-only. Stacked on draft #212, under scientific support obligation #195 and independent evaluation obligation #177. No production historical-evidence reuse or `VALID` is authorized.

## Question

The previously checked Lean theorem is `historical_claim (n : Nat) : op n = n := Eq.refl n`. The imported source module now contains two definitions:

```lean
def base (n : Nat) : Nat := n
def op (n : Nat) : Nat := base n
```

The exact proof expression and claim are exported from the native patched source environment, independently rechecked in a second process without importing the historical theorem, and retained for target use.

The target configurations are separate native Lean 4.35 builds with the exact same target claim recorded as an **unproved axiom placeholder**. One target changes only `base` to `0 + n`, leaving `op` text and native structural AST unchanged. Another adds an unrelated definition without changing `base` or `op`.

The experiment asks two non-equivalent questions:

1. Do the native source and target checker environments **report** identical checked expression ASTs for `op` and for its directly referenced `base`?
2. Does the actual patched Lean target kernel adjudicate the **identical historical source proof expression** as admissible under the separately built target context?

The first observation informs an oracle-blind, conditional prediction. The second is reserved as a separate reference outcome. The experiment's two native declarations are a constructed *known finite chain*, not a generic support extractor.

## Pre-replay boundary and integrity

`lean_native_transitive_declaration_probe_v1.lean.txt` is appended to the existing strict structural native probe **in the same Lean process** and records the actual `base` type/value AST and `op` value AST seen there. It rejects missing definitions and unsupported structural expression constructors. The observer sets completeness, historical replay and reliance authority to false.

`lean_native_transitive_preoracle_v1.py` first invokes the complete original #210 source/target witness validation, including the hash-pinned Lean executable, source proof, separate source recheck, exact unproved target claim, and imported module bytes. It verifies that both native observers agree on `op`. For the strict `Nat`/`Eq`/`Eq.refl`/`op`/`base` fixture, it compares `op` and `base` AST identity and inspects direct referenced names in the recorded ASTs. Unknown names and unsupported ASTs never authorize a candidate.

This is deliberately **not a complete kernel-relevant support relation**. Native source/target environment binding is observed by the workflow without independent issuer attestation. Core `Nat`/`Eq` semantics, universes, quotient/reduction settings, imported metadata, and full kernel configuration are not proved invariant by this observation. An equal structural AST for `base` does not establish equality of its semantics if its own dependencies or checker context drift. Thus a candidate is explicitly conditional and non-controlling.

## Frozen development controls

| Context | Observed `op` AST | Observed `base` AST | Expected oracle-blind outcome | Expected actual target replay |
| --- | --- | --- | --- | --- |
| Independently rebuilt unchanged module | Same | Same | `CONDITIONAL_TRANSITIVE_CANDIDATE` | `ADMISSIBLE` |
| `base n := 0 + n` | Same | Changed | `REVALIDATION_REQUIRED` | `INADMISSIBLE` |
| Unrelated extra declaration | Same | Same | `CONDITIONAL_TRANSITIVE_CANDIDATE` | `ADMISSIBLE` |

These are predeclared expectations, not claimed measurements until exact-head CI completes. For all three targets the previously checked `Eq.refl` proof expression and target claim AST stay unchanged.

The preoracle receives **no target replay transcript, verdict, proof constructor or new target proof**. The workflow writes predictions and SHA-256 commitments before invoking target historical replay and verifies the committed artifacts remain unchanged after adjudication.

## Interpretation and link to the North Star

This tests a real checker-level manifestation of the model observation in #212: agreement on an immediately referenced declaration does not suffice if its body recursively depends on a changed definition. It establishes experimental evidence for why an evidence-applicability system needs a documented and adequately supported *transitive* context relation.

A native replay control does not prove semantic-support completeness or future generalization. The existing #212 theorems cover a deliberately small, independently defined trace calculus; the new Lean control **does not establish a formal refinement from that calculus to `Lean.Kernel.check`**.

The long-term objective is to maintain, across changing specifications, environments, implementations, evaluators and observations, a verifiable account of which claims remain justified, by what evidence, under what premises, and which verification/repair work is warranted. A reliable transitive support extractor and an actual-kernel correspondence theorem are needed before promising safe, replay-free evidence reuse. Repair minimization and prospective utility remain further research problems.

## Next gates

The next formal result must cover a precisely specified native Lean fragment, including conversion/reduction and the metadata used by its kernel, or retain explicit additional assumptions. Separately authenticate historical evidence, loaded environments and relying policies. Compare independent preoracle outcomes against same-certificate replay on unseen, prospectively sampled cases under #177, and measure verification work only after the applicability boundary is scientifically credible.

This fixture remains excluded from all confirmatory holdouts, and no changes to OVK production decision semantics are authorized.
