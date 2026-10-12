# Strict pre-oracle byte-identity candidate — bounded Lean 4.14.0 development v1

**Status:** development predictor, non-controlling, stacked on #196. No target historical-proof replay occurs in its input path. Its output vocabulary deliberately excludes `VALID`.

## Concrete purpose

Test the strongest defensible *small* sufficient-condition hypothesis available before closing the full Lean dependency-support theorem: if the **exact old certificate**, exact target statement, exact pinned kernel and all **natively reported loaded imported module bytes** are held identical, then target checking of the old certificate is expected to be preserved **conditional on complete environment reconstruction**. A changed imported module makes this conservative byte-identity rule abstain and request revalidation. Repository edits outside the loaded/imported environment do not alter its decision.

This is a strict whole-reported-import-environment predicate, not a fine-grained dependency slice. It can revalidate unnecessarily when an unrelated declaration inside an imported module changes. The rule is useful as a restricted baseline and independent disagreement control, not an optimized production repair algorithm.

## Inputs and timing

`lean_preoracle_byte_identity_v1.py` consumes only:

1. The prior native, source/target separately installed environment inventory, including every module name reported by Lean's imported-module enumeration.
2. The original serialized source proof/type AST with its hash and the separate source-process native kernel verification witness.
3. The independently observed **unproved** target claim AST (revalidated from the pre-oracle structural log).
4. Fresh native target *reference-only* environment enumeration with each candidate target module installed. This probe invokes no source certificate.
5. Exact `.olean` contents re-read from both designated installation roots and the pinned Lean 4.14.0 binary digest. A missing or redirected module fails closed.
6. No oracle result, target certificate checker response, fresh target proof, retrospective label, or future target adjudication fields.

The native workflow creates **both prediction outputs and their SHA-256 receipt before either target historical-certificate replay**. Only then does a separate Lean invocation run the #196 oracle. Both branches of the experiment are previously exposed development fixtures. The saved digest receipt is a sequencing and immutability control **inside one hosted runner**, not proof of independently enforced oracle isolation.

## Decision function

Let `E0` and `E1` denote the collections of natively reported loaded imported module names. Let `H0(m)` and `H1(m)` be exact `.olean` byte digests from separately provisioned pinned installations.

- `UNRESOLVED`: unknown or changed imported-module inventory, missing target import, incomplete acquisition, invalid source evidence, unrecognized toolchain, malformed AST, mismatched identity or missing provenance. Certain corrupt inputs produce a hard error and no result file.
- `REVALIDATION_REQUIRED`: validated source certificate, unchanged target claim AST and module inventories, with at least one installed imported `.olean` byte digest/length changed. No claim that changed bytes invalidate the historical certificate.
- `CONDITIONAL_IDENTITY_CANDIDATE`: validated source certificate, identical target statement AST, same pinned checker binary, same reported imported-module inventory, exact byte equality for **all** reported imported modules, and no unsupported authority claims in evidence. This is a candidate under **unproved completeness and authenticity premises**. It is never a production `VALID`.

These statuses express pre-oracle evidence comparison. The historical-certificate reference adjudicator emits `ADMISSIBLE`, `INADMISSIBLE`, or `UNDETERMINED` from native kernel replay. Those concepts must remain separate.

## Conditional proof obligation

Fix a historical proof Expr `p`, type `q`, source kernel environment `C0` and target `C1`.

Assume:

- A1. `p` was genuinely accepted by the designated source kernel against `q`; the source receipt and serialized AST are authentic.
- A2. The target claim is the **same checked Expr**, and the exact historical proof Expr is retained without modification.
- A3. The same trusted kernel binary, checker flags and configuration are used with the same observable deterministic checking semantics.
- A4. The target *kernel-relevant* environment for all operations used by checking `p : q` is semantically identical to the source environment. In particular, the native loaded-module inventory is complete and corresponding authenticated `.olean` bytes, imported constants, axioms, options, primitives and kernel state produce the same relevant declarations.
- A5. No revocation, expiry, reliance-policy change, or invalid source provenance applies.

Then `Kernel.check C1 p` and `Kernel.isDefEq C1 ... q` are expected to reproduce the source acceptance. **The actual code establishes some observable byte identities; it does not discharge A3–A5 in their entirety or machine-check this conditional theorem.** In particular, the claim that file-byte equality determines every relevant kernel state is an unproved extraction and environment-semantics obligation. Even perfect byte equality of reported modules does not automatically establish policy eligibility.

## Mandatory negative controls

The development workflow predicts both cases *before* the independent oracle:

- Equal imported `op n := n`: `CONDITIONAL_IDENTITY_CANDIDATE` with actual oracle `ADMISSIBLE`.
- Imported `op n := 0 + n`: `REVALIDATION_REQUIRED` with actual oracle `INADMISSIBLE`; the target claim is nevertheless freshly provable.
- A source proof receipt mismatch or source `.olean` substitution is rejected.
- Absent target imported module or changed loaded module inventory is `UNRESOLVED`.
- Target statement tampering, target oracle contamination, and unsupported provenance flags are rejected.
- An unrelated file edit outside the loaded import inventory leaves only the *conditional* candidate decision unchanged.
- All predictor output records explicitly state `oracle_consulted=false`, `target_historical_proof_replayed=false`, `production_reliance_authorization=false`, and `module_semantic_support_complete_proved=false`.

## Research conclusion boundaries

These are development controls using known, constructed outcomes, **not** an independent held-out estimate of false reuse, and no evidence of cost savings. Equal hashes across natively reported module inventory are stronger than a caller-supplied semantic-support boolean, yet cannot establish semantic-completeness, supply-chain authenticity, policy approval, or an OVK refinement proof. The next scientific step is a formal and independently reviewed characterization of the kernel environment fragment and provenance contract, followed by a genuinely prospective #177 study. Do not merge these research branches into production or promote candidate decisions to `VALID`.
