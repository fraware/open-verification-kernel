# Lean native source/target axiom-support observation

**Research-only, development controls.** This experiment extends the
source-only, second-process kernel check in draft PR #192. It makes
native axiom dependence an explicit, typed evidence field under a
controlled source/imported-target transition.

## Checked mechanism

Lean 4.14.0 ships `Lean.collectAxioms` in
`src/Lean/Util/CollectAxioms.lean`. It recursively visits declaration
type/value references and records encountered `axiomInfo` declarations.
The native `#print axioms` command uses the same implementation.

The new native probe
`experiments/rtk/lean_axiom_dependency_probe_v1.lean.txt`
records, separately:

- Direct constant references from the source checked historical theorem
  declaration, including its source proof.
- Direct references from the imported `op` definition.
- A transitive `collectAxioms historical_claim` inventory in the source
  environment, including each encountered axiom's native constant name
  and declaring module.
- A transitive `collectAxioms op` inventory in each imported environment.

The target is an explicitly **unproved** synthetic `axiom
rtk_unproven_target_claim` with the same claim type. Its placeholder is
never interpreted as proof evidence; the experiment deliberately excludes
`collectAxioms` on that placeholder from the source-proof dependency
inventory. The target old proof is never replayed.

## Adversarial target-only axiom injection

After collecting the original source and target profiles under separately
installed pinned Lean 4.14.0 toolchains, the workflow recompiles **only**
the target imported module `RTKSemanticSupport` with:

```lean
axiom rtkExternal (n : Nat) : Nat
def op (n : Nat) : Nat := rtkExternal n
```

The module name, imported `op` declaration name and type, and synthetic
target goal text are preserved. A second native target introspection run
records the newly introduced `rtkExternal` axiom and its imported module
provenance.

`experiments/rtk/lean_axiom_support_v1.py` validates native record schema,
constant names, unique sorted axiom inventories, imported module
identities and prior target module membership. It rejects `sorryAx`,
new authority or oracle flags, synthetic target proof-axiom contamination,
missing source theorem references and an unobserved injected axiom.
Its output is `REVALIDATION_REQUIRED` and historical applicability
`UNDETERMINED`.

The separate Python unit tests are synthetic negative controls; only the
GitHub Actions native run establishes that `Lean.collectAxioms` was
actually called on the pinned checker and real imported module.

## Explicit limitations

- `Lean.collectAxioms` **silently ignores an unknown referenced
  constant** (the implementation's `none => pure ()` branch). The
  observation is consequently **not a formally established complete
  semantic support closure**.
- The native axiom listing captures names and module origins, not
  independently authenticated bytecode, definitions, checker semantics,
  axiom-authority policies or signed reliance rules.
- Imported module `.olean` hashes from prior controls identify specific
  compiled file bytes, but an axiom inventory does not prove their
  complete transitive dependency or policy closure.
- Different axioms are not proof of target theorem falsity. The target
  goal remains unproved in this experiment. A drift-triggered
  revalidation recommendation is conservative.
- The fixture is constructed and previously inspected. There is no
  prospective blinded sample, independently governed native oracle,
  calibrated false-reuse rate, or production authorization.

Artifacts and execution code:

- `experiments/rtk/lean_axiom_dependency_probe_v1.lean.txt`
- `experiments/rtk/lean_axiom_support_v1.py`
- `tests/test_rtk_lean_axiom_support_v1.py`
- `.github/workflows/rtk-lean-axiom-support-v1.yml`

## Next research gate

Produce a checked and explicitly bounded dependency closure with
**failure on missing constant declarations**, bind its declaration kinds,
type/value ASTs, universe parameters, axiom names, imported module
artifacts, checker and environment configuration to authenticated source
and target revisions, then separately specify a relying-policy transport
relation. Any `VALID` decision must await proven semantics or calibrated,
independently evaluated restrictions, with prospective predictions sealed
before any native target replay.
