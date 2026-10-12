# Lean 4.14 imported proof references and .olean byte binding

**Development-only, non-controlling.** The source control and target-goal
fixtures were inspected before this experiment. No prospective independent
holdout was opened and no empirical reliability rate is estimated.

Implementation:
`experiments/rtk/lean_imported_proofrefs_v1.py`.
Native executable workflow:
`.github/workflows/rtk-lean-olean-proofrefs-v1.yml`.
Tests: `tests/test_rtk_lean_imported_proofrefs_v1.py`.
Parent research: draft PRs #184–#185.

## Purpose

The previous native support probe discovered the historical source proof's
imported dependencies, including `Eq.refl`, and the target's unproved
claim/definition context, without checking the old proof on the target.
That left a missing target-environment compatibility check for the
source's **proof-only references**, since a goal type alone does not
reference every constant appearing in an historical proof expression.

This experiment implements two bounded checks.

First, source-native checked proof metadata determines the exact finite
list of imported constant names. A deterministic generator emits a Lean
`run_cmd` block of **environment lookups** over precisely those names.
The block is executed in both a source proof environment and a target
*unproved goal* environment. For each constant, it records its name,
declaration kind, imported-module name, and native type representation.
It never reconstructs, elaborates, executes, or rechecks the old proof
term on the target.

Second, the Python adapter resolves each observed imported module
`Foo.Bar` within the pinned Lean toolchain installation to
`lib/lean/Foo/Bar.olean`, refuses absent files, symlink redirects
and path traversal, and hashes its **exact on-disk bytes** using SHA-256.
The script is bound to the exact measured Lean 4.14.0 Linux executable
SHA-256
`eacf754d25ae86ea076882a34b9444f2485659d9df4266b821443b28ca95a215`.
Every digest and installed module path is emitted to a versioned record.

The source reference inventory, native source and target lookup logs,
and exact `.olean` fingerprints are preserved in the workflow artifact.

**Expanded loaded-environment inventory.** The Lean native reference probe
also records `Environment.allImportedModuleNames` on both sides. The
current pinned development environment reported **1,012 loaded modules**
on each side. The adapter confirms identical module-name inventories,
then resolves and hashes every loaded module's installed `.olean` bytes,
not only the direct proof references. File reads use streaming SHA-256,
with bounded inventories (up to 2,048 modules), file sizes (under 128 MiB),
and aggregate size (at most 4 GiB). The emitted record contains all
per-module digests, a canonical JSON inventory digest and the exact
aggregate byte count. A changed `.olean` file will change its SHA-256.

This is an **exhaustive inventory of modules reported as loaded in that
particular native Lean process**. It is not a proof that every semantic
dependency relevant to historical evidence is represented, that native
expression serialization is canonical, or that all nonmodule environment
inputs were captured. The source/target fixture deliberately uses the
same installation; the inventory matching observation is therefore
a reproducibility control and not a cross-installation result.

## Scope of each result

A successful bounded observation establishes only that, in the
**one installed checker/environment used by this development fixture**,
all source-imported proof references were present in the target
environment with the same recorded declaration kinds, imported-module
names and diagnostic type representations. Their exact installed module
file bytes were hashed and their provenance paths recorded, alongside an
inventory of all loaded-module file identities under this process.

It does **not** establish that every dependency of the reference's
`.olean` or transitive constant type/value has been captured. Two
libraries with the same exported declaration type but different
implementations may be incompatible for historical elaboration.
Imported module names by themselves are insufficient; hashing directly
referenced modules strengthens reproducibility but does not prove
completeness of their transitive import closure.

Both source and target use **the same Lean installation** in this
control, so matching installed `.olean` hashes are expected by
construction. A later cross-version study must independently collect
source- and target-specific imported module closure manifests under
two genuine build environments and define the admissibility transport
rule between them.

The names and types of the old proof's dependencies are lookup
features. Checking their presence is **not** an old-proof replay,
a kernel proof certificate migration or a proof of target theorem
truth. The target goal remains a synthetic `axiom` placeholder
solely for type and context introspection.

The machine-readable record fixes these negative findings:

- `different_source_target_module_installations_compared=false`;
- `target_proof_supplied=false`;
- `target_old_proof_replayed=false`;
- `target_goal_established=false`;
- `transitive_import_semantics_proved=false`;
- `lean_expression_serialization_canonical=false`;
- `transport_applicability_established=false`.

No predicted `VALID` is authorized for production reuse because this
development-only module lookup succeeded.

## Security and falsification controls

The adapter refuses an unpinned Lean checker executable, missing
or redirected `.olean` artifacts, malformed or duplicate native
reference records, missing target constant declarations, changed
reference names/kinds/types/modules, and unexpected target claim
definitions. The unit tests include module-byte drift and symlink
attacks. Exact tool installation provenance and external attestation
of native runner artifacts are still separate trust questions.

## Required next phase

1. Extract exact transitive `.olean` import closure from source and
   target *separate installations*, with checker and release IDs.
2. Reconstruct native source proof-term dependencies by checking
   normalized kernel expressions or authenticated constant
   representations, including imported axioms and reducibility.
3. Validate this representation against negative controls in which
   module names and theorem text are stable but imported module bytes
   or semantics differ.
4. Freeze genuine SUT predictions before any target native replay in
   independently selected repository revisions, then adjudicate with
   a separately controlled oracle.

Until these are satisfied, this development probe is evidence of
native instrumentation and exact-byte reproducibility only.
