# Same-name imported Lean module drift — native development experiment

This experiment tests a concrete cross-artifact invalidation mechanism:
the theorem statement and referenced imported declaration's **name and
type** are unchanged while the referenced imported **definition body**
changes. The experiment is synthetic development evidence, already
designed with knowledge of the expected outcome; no prospective RTK
accuracy statistic or authorization claim follows.

## Controlled module transition

The source environment includes an imported module called
`RTKSemanticSupport` with:

```lean
def op (n : Nat) : Nat := n
```

The target imports the **same module name**, replacing the definition
with:

```lean
def op (n : Nat) : Nat := 0 + n
```

Both environments use the same intended formal claim,
`historical_claim (n : Nat) : op n = n`. The source's historical proof
source is exactly `Eq.refl n`.

The experiment independently provisions two pinned Lean 4.14.0
installations. It first compiles *identical source module content from
the identical compilation path* using both tools and asserts equal
`.olean` file SHA-256s. That controls for differing toolchain
filesystem roots. It then recompiles the target's same-name module
using the changed definition, leaving the source module unchanged,
and asserts distinct `.olean` file digests.

The target pre-oracle program contains an explicitly **unproved
`axiom rtk_unproven_target_claim`** with the same formal claim type.
The axiom acts only as a claim-type placeholder. A native
`ConstantInfo` lookup retrieves the imported `op` declaration in
both environments and compares diagnostic native type/value
expressions. Expected development observation:

- Same imported symbol `op` and module `RTKSemanticSupport`.
- Same native declaration type and theorem statement type.
- Different native value expression for `op`.
- Both source and target historical-proof reference inventories
  resolve, including `op`, `Eq.refl`, `Eq` and `Nat`.
- The only changed loaded `.olean` module bytes are associated
  with `RTKSemanticSupport`, with all other modules hashed.
- The pre-oracle environment comparison reports `DRIFT_DETECTED`
  and **`transport_applicability=UNDETERMINED`**.

Only **once the pre-oracle observation has been written** does a
separate development-control workflow step run the exact historical
proof source against the changed target module and a separate fresh
proof. The expected native result is that the old proof is rejected
and a fresh `Nat.zero_add n` proof is accepted.

This ordering is recorded in one GitHub Actions run. It is **not**
cryptographic prediction sealing, independent oracle governance or
a prospective blinded experiment: the fixture and expected outcome
were known before development. It is an engineering diagnostic.

## Why this case is useful

A textual or declaration-type identity test would miss the semantic
definition change. A module-name identity test would also miss it.
Exact imported `.olean` fingerprints detect byte changes, and a
native imported `ConstantInfo.defnInfo` inspection demonstrates
that the referenced definition value expression changed.

The module-byte mismatch alone cannot prove that the previous proof
has become invalid: `.olean` byte changes include serialization and
metadata differences. Here the independent native replay step
observes the old proof rejection for this *particular* synthetic
fixture, establishing the phenomenon under the pinned checker.
The native replay result must never be fed back to the pre-oracle
predictor and relabeled as a held-out observation.

## Limits

- The source/target builds are separately installed but not
  independently administered; they share a runner and upstream
  compiler distribution.
- `Expr.repr` is a diagnostic representation, not proven canonical
  kernel-expression serialization.
- Imported module contents and support names are represented by
  fingerprints, without a theorem connecting them to all Lean
  kernel, elaborator, toolchain and policy dependencies.
- A target proof failure is not a refutation of the target claim;
  the independent fresh proof establishes the claim for this fixture.
- The native experiment provides no general RTK false-reuse bound,
  statistical calibration, proof-certificate transport theorem,
  production reliance authorization or savings figure.

Files:

- `experiments/rtk/lean_imported_drift_fixtures_v1/`
- `.github/workflows/rtk-lean-imported-semantic-drift-v1.yml`
- `experiments/rtk/lean_dual_installed_env_v1.py` (parent PR #187)

Keep this case **development-only** and disjoint from the frozen
v0/v1 and proposed v2 confirmatory research corpora.
