# Axiom-free Lean historical-applicability fragment — development v1

**Status:** draft successor to #201, under #195; prospective independent evaluation remains governed by #177. No production reliance authority.

## Discovered limitation

Lean `--trust=0` verifies the kernel well-formedness of declarations loaded from imported modules and rechecks the exact historical proof; it does **not** turn imported axioms into derived theorems. An arbitrary axiom declaration is accepted as an assumed proposition under its own trust model. Thus a zero-trust proof can still depend on an external logical assumption, and its acceptance alone is insufficient evidence that its proposition is axiom-free or eligible under a relying organization's policy.

The repository already exports two native observations:
- `Lean.collectAxioms` reporting axioms transitively associated with the checked source theorem and imported `op` declaration; and
- strict bounded `ConstantInfo.getUsedConstantsAsSet` declaration graphs for the same source and target objects.

Before this PR, the actual pre-oracle predicate consumed declaration graphs but did not restrict transitive axioms. Existing axiom-delta experiments only reported the difference, without acting on candidate eligibility.

## Research-only exclusion rule

`evaluate_preoracle_identity` now requires native **source and target axiom-support observations**, in addition to the already mandatory declaration graphs and strict zero-trust kernel-header evidence. Native axiom logs are validated by the existing strict `_read_record` parser. The predicate:

1. Binds the axiom and declaration-graph reports to the same source checked theorem and target unproved placeholder identities.
2. Compares direct constant reference sets for the source/target root and imported `op` across these two native probes; disagreement raises a hard error.
3. Rejects any transitive source historical-proof axiom and any transitive imported-`op` axiom seen in either source or target environment.
4. Independently refuses any reachable `axiom` declaration in either strict reference graph except the **target unproved claim placeholder itself**. This placeholder is a goal representation, never evidence of a proof.
5. If an axiom is observed, reports **`UNRESOLVED`** with `observed_axiom_dependency_outside_axiom_free_fragment`; it never emits a conditional candidate or a reliance authorization.

Clean axiom-free controls continue to emit the narrower `CONDITIONAL_IDENTITY_CANDIDATE` or `REVALIDATION_REQUIRED` development statuses. These never become `VALID`. Both output flags `transitive_axiom_support_complete_proved` and `axiom_policy_authenticated` remain **false**, even for an observed empty set.

The current rule is a deliberately strict **axiom-free research fragment**, not a general axiom allowlist, and is more restrictive than Lean's ordinary logic, which has intentionally trusted axioms and primitive quotient principles. Other supported mathematical applications will need an explicit, independently approved axiom policy. A declared `sorryAx` is separately rejected by the existing native axiom parser.

## Native negative controls

The pinned Lean 4.14.0 workflow now captures axiom probes in the source and both target contexts under `--trust=0`, **before** target historical-certificate replay. The original default-trust probes are captured separately.

A new target-only development branch compiles an imported module with
```lean
axiom rtkExternal (n : Nat) : Nat
noncomputable def op (n : Nat) : Nat := rtkExternal n
```
under `--trust=0`. Its unproved target claim, imported references, bounded declaration closure, axiom dependencies and kernel header are all observed natively. The pre-oracle must abstain with `observed_axiom_dependency_outside_axiom_free_fragment`, even though the native compiler accepted the imported axiom declaration.

The existing equal/changed definition predictions are sealed as separate records. This third `UNRESOLVED` development record is also sealed **before** the independent source-certificate target-replay oracle. No result from that oracle is read by the pre-oracle.

Synthetic adversarial Python controls cover source-proof axioms, source/target imported axioms, `sorryAx`, missing/malformed axiom logs, direct-reference disagreement, and the exclusion of fake production-policy authorization.

## Precise non-claims

- Two native reports of `ConstantInfo` reference data and `collectAxioms` agreeing do **not** establish complete Lean kernel dependency semantics. Both can share omissions; `collectAxioms` itself has limitations about unresolved referenced constants.
- Zero trust does not authenticate the Lean executable, source issuer, imported artifacts, runner, revocation policy or target specification authority.
- An empty observed axiom set is **not** an independently certified global proof that all axioms are absent, nor a general proof of applicability preservation.
- No theorem has been proved that the actual Lean kernel's certificate checking behavior is preserved by the current pre-oracle abstraction. The restricted Nat evaluator proof in #199 does not close this gap.
- The synthetic developer controls remain **outside** the prospective blinded empirical sample of #177, and no false-reuse or cost-saving estimates are claimed.

Keep the research branch draft and unmerged; production `VALID` and signed relying authority remain excluded.
