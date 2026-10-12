# Lean 4.14 structural Expr decoder and native source-kernel roundtrip

**Development-only.** This extension of draft PRs #189 and #190 executes a
restricted constructor-level encoder and a separately written decoder
inside the pinned Lean 4.14.0 runtime, comparing reconstructed native
expressions with the originals.

The implementation is limited to known checked source/theorem fixtures.
It does not prove decoder correctness for all Lean expressions, authenticate
the native runner, infer historical target applicability or authorize reuse.

## Method

`experiments/rtk/lean_expr_decoder_roundtrip_v1.lean.txt` is appended
to the same Lean input file that contains the previously implemented
`lean_structural_expr_probe_v1.lean.txt` encoder. The decoder explicitly
handles Name constructors (anonymous/string/numeric components), Level
constructors (zero, successor, max, imax, parameter), and Expr
constructors (bound variables, sorts, constants/universe instantiations,
applications, lambdas, forall binders, let binders, literals and
projections).

It rejects unsupported free/metavariables, metadata, invalid tags and
arity, malformed values and excessive recursion. For the source native
theorem, source proof Expr, imported `op` type and definition body,
and target unproved goal/type and imported `op` type/body, it verifies:

1. Encoding the original native Expr and decoding the resulting AST
   reconstructs an expression equal to the original.
2. Encoding the decoded Expr produces identical structural JSON AST bytes.
3. The **decoded SOURCE historical theorem proof Expr** is accepted by
   `Lean.Kernel.check` in the source Lean environment.
4. Deliberately substituted imported-definition JSON does not compare
   equal to the actual declaration, and unsupported metavariable
   constructor injection is rejected.

The native workflow
`.github/workflows/rtk-lean-structural-decoder-v1.yml`
uses two separately installed, content-pinned Lean 4.14.0 toolchains
and the same previously exposed controlled imported-definition drift
fixture. It emits source and target native decoder logs, then
`experiments/rtk/lean_expr_roundtrip_v1.py` strictly correlates the
outputs to the prior independent structural-extraction logs. Target
remains `axiom rtk_unproven_target_claim ...` for **type inspection
only**, with no proof body, no old source proof replay and no fresh
target proof.

## Strength and limits of the evidence

If the native job passes, it establishes an executable roundtrip
**for exactly the checked expressions encountered in this development
fixture**, plus independent invocation of Lean's kernel type checker
on a reconstructed source proof. The decoder is distinct source code
from the encoder but **executes in the same native process** and is
not formally verified. `Expr` equality is not itself a proof of
completeness or portability. This is not a proof of a generic canonical
serialization, nor externally attested native provenance.

The decoded source proof is kernel-checked under its **source**
environment. A target theorem or target historical evidence
applicability has not been established. Imported `.olean` file
identities, kernel configuration, axioms, relying policy and source/target
semantic support closure are not yet shown to form a complete
applicability certificate.

The positive output is limited to the following flags:

- `native_decode_encode_roundtrip_verified=true` in the observed fixture.
- `native_source_decoded_proof_kernel_checked=true`.
- `target_unproved_goal_roundtrip_verified=true`.

Negative flags remain:

- `native_decoder_formally_verified=false`.
- `independent_log_provenance_verified=false`.
- `complete_semantic_support_established=false`.
- `target_old_proof_replayed=false`.
- `target_claim_established=false`.
- `historical_transport_applicability=UNDETERMINED`.
- `reliance_authorization=false`.

This does **not** replace #190's previously recorded
`native_expr_decoder_roundtrip_verified=false` envelope field:
that record is an earlier versioned contract created without a native
decoder witness. The decoder output is a separate evidence record
pending a future authenticated cross-artifact contract.

Future acceptance must verify decoder AST inputs from independent
serialized files, kernel type identity and universe context,
full transitive declaration/axiom closure and policy applicability,
then conduct sealed independent prospective experiments.
