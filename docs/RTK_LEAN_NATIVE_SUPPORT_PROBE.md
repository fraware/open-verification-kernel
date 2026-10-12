# Native Lean proof-support extraction — bounded development implementation

**Classification:** native execution verified for a *self-contained development
fixture*, with deliberately incomplete imported-library support.
This component does not establish the soundness of Lean proof transport,
independent oracle separation, or a confirmatory false-reuse rate.

## Implemented native stage

`experiments/rtk/lean_native_support_footer.lean.txt` executes through
Lean's `run_cmd` command elaborator after kernel/elaborator acceptance of a
named theorem. It queries the native `Environment` and `ConstantInfo`
objects, follows referenced constants via the Lean 4.14.0
`ConstantInfo.getUsedConstantsAsSet` API, and records diagnostic expression
representations of each locally defined constant's type and value.

A declaration is classified as *local to the current source environment*
using `Environment.getModuleIdxFor?` (the API actually present in pinned
Lean **4.14.0**). This yields automatic recursive expansion of local
definitions and theorem references. Imported constants are recorded as
opaque name/type-classification boundaries with **no body expansion**.

This source is grounded in upstream `leanprover/lean4` release
`v4.14.0` at commit
`410fab7284703f41660ca2454218dcca9b2ec896`. The relevant APIs are
implemented in `src/Lean/Environment.lean` and
`src/Lean/Util/FoldConsts.lean`.

The dedicated workflow
`.github/workflows/rtk-lean-native-support-probe.yml`
uses the previously measured and now checked Linux Lean binary SHA-256

```text
eacf754d25ae86ea076882a34b9444f2485659d9df4266b821443b28ca95a215
```

and constructs two native Lean source files from the same fixture
family used for independent historical proof replay in draft #184.
The *source native input* has `def op (n : Nat) := n` and
proof `Eq.refl n`; the *target native input* uses
`def op (n : Nat) := 0 + n` and a fresh proof `Nat.zero_add n`.
The statement `theorem historical_claim (n : Nat) : op n = n`
is unchanged.

The native probe has already been observed to output
`Lean.Expr` data for the theorem and `op`, including a changed
native value expression for the referenced definition. The
source and target **both have fresh accepted proofs**, so this stage
is not an independent oracle for the old proof's target admissibility.

## Machine-readable partial projection

`experiments/rtk/lean_native_support_projection.py` parses the
native-emitted JSON and revalidates exact record shape, root identity,
symbol uniqueness, dependency reference closure, and opaque imported
boundaries. It calculates deterministic SHA-256 fingerprints from the
native diagnostic type/value representations, classifies imported
boundaries, and flags a changed local `op` definition.

These fingerprints are **version-pinned diagnostic fingerprints**.
`Expr.repr` was not proved canonical or stable across Lean builds,
and imported constants do not contain their type/value bodies.
The resulting projection fixes:

- `support_claimed_complete=false`;
- `semantic_serialization_soundness_established=false`;
- `source_authenticity_verified=false`;
- `applicability_proved=false`.

Even if the native workflow passes, the projection does not
independently authenticate its input file or GitHub Actions artifact.
The native log and checked source SHA-256 values are archived
separately so an external reviewer can verify their identities.

## What this proves and what it leaves open

The positive engineering fact is that **real Lean-native checked
expressions and dependency names are accessible** and suffice to detect
the deliberate local definition drift under the pinned checker. This
is a concrete implementation bridge from lexical source tests to
kernel/elaborator data.

The current procedure does **not** establish complete transitive proof
support. Imported dependencies are deliberately opaque; we have not
captured environment/olean object hashes, native axiom trust closure,
universe levels or canonical kernel-expression bytes. The target
program includes a fresh proof, and this output therefore cannot
serve as a pre-outcome target prediction in a blinded evaluation.

The next acceptance gate is an isolated producer that reads target
environment/claim metadata *without accepting the historical proof or
revealing a native target PASS/FAIL*. That producer must reconstruct
the same exact claim, validate imported-environment identity and policy,
and handle dependency kinds unsupported by the current projection.

A verified native source graph is useful research evidence. It does not
yet justify turning the prediction `VALID` into a software-reliance
authorization. No production merge or release authority is modified.
