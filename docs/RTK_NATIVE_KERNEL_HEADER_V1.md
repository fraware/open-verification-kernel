# Native kernel-header state binding (Lean 4.14.0 development v1)

**Status:** research-only successor to draft #199. No production reliance authority. [Issue #195] captures unresolved completeness and transport-soundness obligations.

## Actual kernel-state dependency missed by prior rule

The pinned Lean 4.14.0 `EnvironmentHeader` in `leanprover/lean4` (tag `v4.14.0`, `src/Lean/Environment.lean`) contains fields `trustLevel : UInt32` and `quotInit : Bool`. The declaration inventory of imported `.olean` file hashes **does not by itself attest to those runtime values**. The Lean source describes `trustLevel` as the kernel trust level (higher levels assume imported constants have been typechecked) and `quotInit` as a flag indicating initialization of quotient declarations, with associated kernel assumptions. Thus, absent direct runtime observations, the previous conditional byte-identity rule left these state dimensions uncontrolled.

## Narrow implementation

- The new native `lean_native_kernel_header_v1.lean.txt` footer executes in a source process with checked `historical_claim` and in each target process with the **unproved** `rtk_unproven_target_claim`. It reads `env.header.trustLevel` and `env.header.quotInit` directly and emits a bounded, typed witness with the declaration root and kind, explicitly denying target proof replay and reliance authority.
- The pre-oracle Python adapter demands exactly one strictly typed native header witness for each source/target root. It rejects missing, duplicate, malformed, wrongly rooted and authority-claiming records.
- A **conservative fragment policy** requires `trustLevel = 0` on source and target and `quotInit = true` on both. Otherwise, even with identical imported module digests, the status is `UNRESOLVED` and the reason is `unsupported_nonzero_kernel_trust_level` or `unsupported_kernel_quotient_state`.
- `native_kernel_header_supported` is true only for the checked pre-oracle candidate or imported-drift revalidation path. `complete_kernel_environment_state_proved` is always false.
- Native logs and records are produced before target historical-proof replay and both pre-oracle predictions are byte-sealed, preserving the intended predictor/oracle separation.

## Native adversarial control

Within the **pre-oracle** phase of the dedicated workflow, the target imported module is restored to byte-identical source semantics and a separate target Lean process is constructed. A target-only `run_cmd` updates its `Environment.header.quotInit` to false; a second `run_cmd` observes that altered native state. The pre-oracle adapter receives the genuine target-side observation along with unchanged original imported-module fingerprints and is expected to emit `UNRESOLVED`. The development control does **not** treat this manipulated state as an authorized target context or use a fresh proof to infer reuse.

A successful test establishes that imported byte equality omits a real mutable environment-header dimension and that the new adapter rejects the particular discrepancy. It does not, on its own, show that the historical certificate would fail under that particular header mutation.

## Remaining kernel bridge

The source/target evidence is a native observation collected by one hosted workflow; it lacks independent attestation. `trustLevel=0` and `quotInit=true` are **not** a proof that all kernel-relevant state has been matched. The imported module inventory plus bounded declaration graphs still leave open the full constant environment semantics, other checker options, independent policy/provenance, trust of loaded modules, exact source/target specification authority and even the completeness of the modeled reference relation.

No formal proof that the predicate preserves `Lean.Kernel.check` exists here. The checked conditional theorem in #199 applies only to its separate first-order Nat evaluation model. The exposed examples do not count toward the prospective holdout in #177. All candidate statuses stay research-only; no `VALID` authorization is introduced.

## Acceptance evidence

Record the exact research commit, SHA-pinned Lean binary and all six full-CI jobs, plus the native workflow run and its specific pre-oracle marker `NATIVE_KERNEL_QUOTIENT_STATE_DRIFT_WITH_UNCHANGED_IMPORTS_REJECTED`. Any failure invalidates completion claims until the exact corrected head is checked. Do not merge the stacked draft branch.
