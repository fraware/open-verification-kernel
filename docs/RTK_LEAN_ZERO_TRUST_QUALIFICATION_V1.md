# Native Lean 4.14.0 zero-trust qualification (development v1)

**Purpose:** replace the unverified assumption that ordinary Lean imports are independently kernel-checked. This successor to draft #200 runs a parallel, explicit `--trust=0` source/target qualification lane. No production reliance is authorized.

## Distinct execution paths

The existing default CLI experiment is preserved. Its actual `trustLevel=1025` produces pre-oracle `UNRESOLVED` and cannot be promoted by a successful target oracle.

The new development lane uses the **same pinned source and target Lean 4.14.0 executable bytes in distinct installations**, invoking the supported CLI flag `--trust=0` for each relevant check. According to Lean's compiler and test documentation, zero trust does not assume imported .olean declarations have already passed kernel checking. The lane also reads the actual `Environment.header.trustLevel` value; the CLI flag alone does not substitute for a native observation.

1. Re-run the *exact serialized historical proof expression* in a fresh source Lean process using `--trust=0`. Validate the original source-payload digest, claim AST, proof AST and prior export manifest via the existing strict second-process witness validator.
2. Obtain a separate source native header observation with `trustLevel=0`, `quotInit=true`. Recompute the native source imported-module list and bounded declaration-closure observations using `--trust=0`.
3. For each separate target imported-definition fixture, compile the target module with `--trust=0`. Use the resulting module bytes and run the **unproved target claim** structural, header, imported-module-reference and bounded closure native probes with `--trust=0`. Do **not** supply the old historical proof to the target processes at this stage.
4. Create a strict zero-trust context receipt binding the exact historical source certificate digest, checked source witness, target unproved proposition AST, native source/target kernel-header receipts, all natively reported imported module names and their exact on-disk `.olean` bytes.
5. Run the pre-oracle predicate on this **separately re-executed** zero-trust evidence. For the known development controls, source-equal target module bytes are expected to produce `CONDITIONAL_IDENTITY_CANDIDATE` and changed imported `op` bytes `REVALIDATION_REQUIRED`, *both subject to unresolved semantic-support and policy premises*.
6. Hash-seal both results and both full zero-trust context receipts **before** the independent historical target-proof oracle begins. The pre-existing default-trust abstentions remain separately sealed.

Native `trustLevel=0` is evidence about the executing import/checking protocol under its documented semantics, not a guarantee against a compromised binary, malicious serialized objects, ABI mismatch or compromised hosted runner. Neither the native text logs nor their hashes provide independent supply-chain attestation.

## Strictly bounded output

`lean_trust_zero_receipt_v1.py` rejects wrong source-payload digest, missing zero-trust checked-source witness, a nonzero native source/target trust header, target evidence containing a fresh proof, mismatched target claim AST, imported module-set differences, missing or redirected `.olean` files, and malformed witness records. It does not ingest the reference oracle or output a `VALID` decision.

The record explicitly reports `semantic_support_complete_proved=false`, `import_integrity_independently_authenticated=false`, `relying_policy_authenticated=false`, `independent_runner_attestation=false`, `oracle_consulted=false` and `production_reliance_authorized=false`.

## Explicit remaining obligations

- Check exact Lean CLI semantics for pinned 4.14.0, including whether `--trust=0` replays all imported declarations and what classes (unsafe, axioms, quotient, opaque, native extensions) remain unverified. Record version and binary SHA.
- Independently bind trusted source/module provenance and axiom/policy admissibility to each historical proof and target statement.
- Formalize and justify a *complete* kernel-relevant support relation and refinement theorem for the allowed Lean fragment; the Nat evaluator model theorem in #199 does not cover the real kernel.
- Use separately governed and sealed, unexposed real revisions in the prospective experiment #177; no development-control false reuse or cost-performance estimate is inferred.
- No production `VALID` or signed ledger reliance authority is created by these research records.

This work remains a stacked, draft, unmerged research branch under #195.
