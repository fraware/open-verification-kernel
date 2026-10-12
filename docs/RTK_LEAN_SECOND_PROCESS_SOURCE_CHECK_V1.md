# Separate-process checked source proof from serialized Lean Expr AST

**Development-only research gate**, stacked on draft PR #191. This step
reconstructs the exact recorded historical source proof Expr and theorem
claim Expr in a **new Lean 4.14.0 process** using serialized JSON bytes on
disk. It verifies that the kernel-inferred type of the reconstructed proof is
definitionally equal to the reconstructed claim in the *designated source*
environment. The historical proof is never replayed against the target.

## Boundary tested

Prior work (#191) decoded and re-encoded native checked Expr values in the
same Lean process that produced the JSON, then type-checked the decoded source
proof. That proved a bounded native roundtrip on known fixtures, with the
serializer, decoder and original native objects all present in one process.

The new workflow serializes only the **source theorem type and proof
expression** into a `rtk_source_proof_payload.json` file. It binds that
file to the real source structural native Lean log and the existing #190
pre-oracle envelope. Its export manifest records the exact SHA-256 of the
JSON bytes, separately generated driver, original source Lean checker input,
source native structural log and proof-expression AST.

A *fresh Lean executable invocation* imports `Lean` and the source version
of `RTKSemanticSupport`. It contains **no declaration or import of
`historical_claim`**. It reads the serialized JSON payload from disk,
decodes the claim and proof Expr constructors, checks encode/decode AST
equality, calls `Lean.Kernel.check` on the reconstructed proof, and calls
`Lean.Kernel.isDefEq` to compare the kernel-inferred proof type with the
decoded theorem claim. It fails closed unless both checks succeed.

The workflow also mutates the serialized theorem claim AST and the proof AST
in **separate negative-control Lean invocations**. Both mutated files must
cause Lean to reject the checker/type-matching procedure. The positive and
negative checker transcript bytes are archived.

## Files

- `experiments/rtk/lean_second_process_source_v1.py` prepares exact JSON
  and source-only native driver files, validates upstream native log and
  claim/proof AST hashes, and writes immutable initial manifests.
- `experiments/rtk/lean_second_process_driver_v1.lean.txt` is the Lean
  second-process reconstruction, kernel checking and type-matching driver.
- `experiments/rtk/lean_second_process_witness_v1.py` cross-checks
  exact JSON, driver, manifest and native witness bytes.
- `tests/test_rtk_lean_second_process_v1.py` covers tampered input,
  changed proof/claim, duplicate witnesses and inappropriate target claims.
- `.github/workflows/rtk-lean-second-process-recheck-v1.yml` executes
  actual pinned Lean native calls, including the two negative controls.

## What a successful test establishes

For this pre-exposed developmental fixture, a distinct Lean process running
the exact registered Lean 4.14.0 executable reconstructs a source historical
proof Expr from serialized JSON bytes and kernel-checks that expression
against the **intended source theorem statement** under its source imports.
The intended theorem declaration itself is absent from the new process.

The result is stronger than a same-process serialization equality check.
It still does **not** establish a general formal decoder-correctness theorem,
a complete source dependency/axiom environment, independent build
governance, cryptographic authentication of the action runner, cross-checker
portability or target historical evidence applicability.

The source context uses a previously constructed imported-definition
fixture and the same Lean release as earlier tests. The target context and
historical target proof are excluded from this second-process check.

Every output fixes
`target_historical_proof_replayed=false`,
`target_claim_established=false`,
`independent_native_process_attestation_verified=false`,
`complete_semantic_support_proved=false`,
`target_transport_applicability=UNDETERMINED`, and
`reliance_authorization=false`.

## Next scientific gates

1. Independently authenticate exact inputs and native execution outputs,
   including source/target installed modules and checker binary hashes.
2. Reconstruct and close the historical proof's complete environment,
   including imported declaration types, values, universe parameters,
   axioms, reducibility, options and relying policy.
3. Define the formal context-transport relation between source and target,
   separately from proof checking and claim truth.
4. Execute previously unexposed, independently selected transitions with
   SUT predictions sealed **before** an independently governed target
   native-oracle check.

No new data from this synthetic fixture is eligible for confirmatory
false-reuse, transport-accuracy or savings estimates.
