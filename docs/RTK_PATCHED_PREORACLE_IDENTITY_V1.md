# Patched Lean 4.35 replay-free identity screen, development v1

**Status:** research-only successor to draft #209, under [#195](https://github.com/fraware/open-verification-kernel/issues/195) and patched-kernel qualification [#205](https://github.com/fraware/open-verification-kernel/issues/205). The pre-oracle never emits a production `VALID` decision and does not consult a target historical-certificate oracle.

## Scientific question

The patched-kernel reference oracle in draft #209 shows that a *single previously checked proof expression*, built from historical source under Lean 4.35.0, is admissible under an unchanged imported `op` and inadmissible under a changed imported definition. That is replay-based adjudication. To test prospective reuse we need a **decision computed without replay**, locked before the oracle independently adjudicates the same source certificate. This experiment deliberately uses a conservative *whole imported-module byte identity* screen, and records both the avoidance of false reuse and the price of unnecessary revalidation.

## Required input and exact scope

`experiments/rtk/lean_patched_preoracle_identity_v1.py` consumes only:

- Exact original serialized checked source proof and statement AST produced under Lean 4.35.0, plus the original source file bytes and the actual native source AST log.
- A distinct native `--trust=0` source recheck witness confirming the exact decoded proof AST and type equality, with the historical theorem absent from the fresh source process.
- The target's **unproved proposition** record and its native structural AST, bound byte-for-byte to the historical claim and pre-replay source payload.
- The compiled source and target imported `RTKPatchedSupport.olean` bytes, and a Lean executable whose SHA-256 equals the independently established patched 4.35.0 development binary hash.

The predicate checks native AST identity and the observed imported `op` type/value AST as an internal consistency check. It rejects malformed, substituted, non-source-checked or authority-bearing records, unsupported checker binaries, and contradictory native declarations. Importantly, it has **no target replay log, target proof, oracle verdict or outcome argument**.

For identical imported module bytes *and* consistent native `op` AST, it emits only `CONDITIONAL_IDENTITY_CANDIDATE`. A changed module byte sequence triggers `REVALIDATION_REQUIRED` even if the observed `op` definition AST is unchanged. No result asserts kernel-context equality, formal semantic support completeness, authenticated issuer provenance, independent relying policy, revocation status, or production reliance authorization.

This bounded screen is **not** an actual Lean kernel soundness theorem. The input binding, trusted checker policy, completeness of imported closure and any unobserved local declarations remain unproved. An entire-imported-module digest is a conservative heuristic; identical bytes without independently authenticated context acquisition do not establish full source-target environment identity.

## Three sealed development controls

The pinned native workflow extends the patched #209 source and target reconstruction with a third developer control. All three target claims have identical structural proposition ASTs and contain no target proof.

| Control | Target imported module | Expected pre-oracle | Independent target replay |
|---|---|---|---|
| `equal` | `def op n := n` | `CONDITIONAL_IDENTITY_CANDIDATE` | `ADMISSIBLE` |
| `changed` | `def op n := 0 + n` | `REVALIDATION_REQUIRED` | `INADMISSIBLE` |
| `unrelated` | `def op n := n` plus `def unrelated n := n` | `REVALIDATION_REQUIRED` | `ADMISSIBLE` |

The unrelated declaration case is **intentional unnecessary revalidation** under the coarse whole-module identity rule. It demonstrates that stricter false-reuse avoidance can impose extra work even if relevant semantics are unchanged, motivating a proven dependency/support frontier and minimal repair.

Every pre-oracle output and its two target native observation records, the source certificate, and target module files are SHA-256 sealed **before any target historical certificate replay**. The oracle later reads the same serialized historical proof expression, in a reconstructed target environment where the original theorem is absent, and reports actual Lean 4.35 kernel results under `--trust=0`. The workflow must verify the seal is unchanged after oracle adjudication.

## Evidence and nonclaims

- These are three **pre-exposed development fixtures**, not blind prospective samples. Three matches of a known oracle cannot establish prospective false-reuse probability, semantic-support soundness, or generalized precision/recall. The calibration protocol in [#177](https://github.com/fraware/open-verification-kernel/issues/177) remains independently governed.
- The source theorem was verified with `lake check --paranoid` in #209; this pre-oracle does **not** independently check the changed target proof using all alternative kernels.
- `source_target_environment_equivalence_proved=false`, `complete_kernel_semantic_support_proved=false`, `external_provenance_authenticated=false`, `patched_checker_relying_policy_qualified=false` and `production_reliance_authorization=false` are explicit output fields.
- This screen does not attempt to lift the abstract Nat model theorem from #199 to the full Lean kernel. To avoid unnecessary revalidation with a declaration-level frontier, issue #195 still needs a genuine semantics-preservation result for a precisely admitted fragment and adequate, authenticated extraction of all kernel-relevant support.
- Any failure or drift in the source/target binary observations, wrong source identity, missing witness, unproved target mutation or runner authorization must stop qualification. No production `VALID` follows from a green development workflow.

Keep the stacked PR draft/unmerged. Judge success only from an exact-head hosted native run and all six normal CI jobs.
