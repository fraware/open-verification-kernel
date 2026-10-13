# Bounded support-preservation theorem — Lean 4.14.0 development model v1

The source of the machine-checked theorem is `experiments/rtk/lean_restricted_support_model_v1.lean.txt`. The dedicated native workflow compiles it using the repository's pinned Lean 4.14.0 installation. It defines a **new finite first-order expression model**, not an encoding of the complete Lean kernel semantics.

## Formal objects

- `Term` is a closed syntax with natural-number literals, named natural-number constant references and binary addition.
- `env : String → Option Nat` assigns optional numeric values to constants.
- `used t` recursively collects all named constant references in the term.
- `eval env t` evaluates terms; missing lookups lead to `none`.
- `Certificate` contains an equation between two terms. `accepts env cert` returns `true` only if **both** terms evaluate to natural numbers of equal value. Two missing evaluations are **not** treated as success.

The following are actual Lean theorems, proved without using an axiom for checker-result equality:

1. `eval_preserved`. Inductively, if source and target environments return the same optional value for every name in `used term`, evaluating that term produces the same optional result.
2. `certificate_acceptance_preserved`. If lookup values match for every name in `support cert`, the model's certificate decision is identical in source and target.
3. `historical_certificate_remains_accepted`. If the source model accepts the certificate and its declared support lookups agree, the target model accepts the same certificate.

The file also checks an explicit *nontrivial* counterexample: `source "imported" = target "imported"` while `source "local" ≠ target "local"`. The exact same model certificate is accepted by the source and rejected by the target. Missing references are rejected.

## Real predictor correction in this PR

The pre-oracle Python visitor in `lean_preoracle_byte_identity_v1.py` previously recursed through the operand of a structural `Expr.proj` while ignoring the projection's **structure Name**. The associated inductive family, constructors and recursor metadata are kernel-relevant context outside that visited operand. Rather than fabricate a complete support rule, **all structural projections are excluded** from the current pre-oracle reuse-candidate fragment. Syntactically encountered projections produce a hard error and **no conditional candidate**, including ones nested under application, lambda, and let expressions. The native Lean encoder/decoder may continue to represent projections for other experiments; only the pre-oracle applicability gate is restricted.

## What the theorem does *not* establish

The checked theorem is valid only for its specified `Term`, `eval`, and `accepts` definitions. It establishes a legitimate preservation property of a **model of name-dependent evaluation**, not a proof that Lean 4.14.0's `Lean.Kernel.check`, `Lean.Kernel.isDefEq` or `ConstantInfo.getUsedConstantsAsSet` refine that model.

The following bridge obligations remain unresolved:

- A verified embedding of an explicit Lean certificate/claim fragment into this model, or a more expressive model tracking dependent types, universes, reduction and axioms.
- A proven relationship between `used` and the actual kernel-relevant support of historical Lean proof expressions, including projections and special kernel forms.
- A proved representation of native environment state, options, imported metadata, local declarations, trusted axioms, safety/opacity, and module bytes.
- Authentication of source evidence and target specification authority; revocation, expiry and relying-policy applicability.
- Independently administered provenance, prospective calibration under #177, and any production authorization.

In particular, the conditional status emitted by #197–#198 stays `CONDITIONAL_IDENTITY_CANDIDATE`; it is never promoted to `VALID` based on this theorem. This PR remains research-only, stacked on #198 and unmerged. The model proof is not counted as support-extractor completeness, nor as a Lean transport theorem.

## Immediate successor

Define an actual *kernel-preserving* restricted Lean type/proof AST fragment and an explicit closed environment contract, or formalize a provenance-bearing full-environment replay rule. Evaluate a pre-oracle SUT only on claims with verified source certification and independently frozen target context, then seal predictions before a separately administered historical-certificate oracle.
