# Reconstructed historical Lean certificate under a patched checker

**Research-only development experiment.** Success establishes a *bounded execution contrast* under **Lean 4.35.0**, not production reliance, general transport soundness or verified source provenance.

## Why this successor exists

The existing Lean 4.14.0 historical proof replay was independently repeated under zero trust in draft #201, but 4.14.0 falls within the affected range of the upstream kernel soundness defect fixed in Lean 4.32.2. Draft #206 independently established functioning patched Lean 4.35.0 `lake check --paranoid` infrastructure, with six checker acceptance markers for a clean minimal fixture. Neither result alone verifies the *original historical Expr* transported to a changed target using the patched kernel.

This experiment produces **new version-bound proof expressions**, never directly reusing v4.14 serialized Expr or `.olean` bytes. The historical certificate referred to here means the same *authored theorem and intended proof source* reconstructed and checked under v4.35.0, not identity of compiler serialization bytes across versions.

## Execution and separation

A source Lake project compiles `RTKPatchedSupport` with `op n := n` and a distinct `RTKPatchedSource` containing `theorem historical_claim (n : Nat) : op n = n := Eq.refl n`. It checks the source module with `lake check --paranoid` and records its acceptance before exporting any certificate for target use.

A native Lean 4.35 expression serializer then exports the *checked theorem's actual kernel Expr*, type AST and proof AST from the source environment. A strict Python adapter records the source proof bytes and digest, retaining the existing versioned restricted Expr schema. A second Lean process imports the support module, **without importing the historical theorem**, reads and decodes the exact original serialized Expr, rechecks it under `--trust=0`, and establishes type equality with the serialized claim.

Two target variants are rebuilt in their own separate Lake project from text. The unchanged target has `op n := n`; the changed target has `op n := 0 + n`. Each has an *unproved* target claim `op n = n`, represented by an axiom placeholder for observation only. Each target native AST record is generated without supplying the historical proof. The two target claim envelopes and the original source certificate are SHA-256 sealed, together with target module binaries, **before any target historical-proof replay**.

Only the later reference-oracle step reads the sealed historical Expr. It runs `Lean.Kernel.check` and `Lean.Kernel.isDefEq` with **`--trust=0`**, asserts the source historical theorem was not imported, rejects substituted target claims, and records actual target-module bytes and same-process trust state. The development-control expectations are `ADMISSIBLE` for identical imported semantics and `INADMISSIBLE` for changed semantics. If actual results differ, CI must fail and the discrepancy must be investigated.

## Provenance, checker and logical distinctions

- The source theorem is independently checked with the patched `lake check --paranoid` multi-checker route. This is **source module checking**, not an independent guarantee that transport to an altered target is correct.
- The target certificate is adjudicated by the **patched Lean kernel** in a separate environment. The independent checkers are **not** claimed to independently adjudicate the changed-target proof expression in this version.
- The source proof AST, statement AST, target native logs, `.olean` hashes, and exact source/target drivers are bound to a single run. The workflow is still hosted by GitHub and the inputs are not independently issuer-attested or governed by a relying policy.
- The safety flag remains **`patched_kernel_security_qualified_for_relying_policy=false`** even if every development control succeeds. Zero trust, patched-version checking and a clean fixture alone do not authorize production reliance.
- No theorem proves that `Expr.getUsedConstantsAsSet`, the imported module byte inventory and selected kernel-header fields are sufficient support for the real Lean kernel. That is the unresolved research obligation in issue #195.
- No hidden prospective false-reuse accuracy is claimed. All source and target fixtures are exposed development controls, excluded from issue #177.

## Acceptance evidence

Exact-head pinned Lean v4.35 executable SHA: `bf8d54e4714cc4b03d3f6bb34c83b7202b87e49c8bfcbff6895c085bb90ceb38`. The installed executable is checked by SHA before native proof execution. Source `lake check --paranoid` must complete successfully in a bubblewrap sandbox, all source and target native programs must succeed, positive and negative historical certificate replay must agree with the expected controls, sealed artifacts must remain unchanged, and the ordinary six-job repository CI must pass.

A successful smoke or legacy v4.14 replay is not a substitute for those checks. The stacked research PR stays draft and unmerged. Full patched checker transport claims and production `VALID` remain blocked by issue #205 and #195.
