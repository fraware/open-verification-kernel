# Native Lean structural Expr/Level encoding — restricted development experiment

**Status:** exact native workflow pending initial execution. Development-only,
non-controlling and separated from prospective evidence-transport confirmation.
This work extends #188 and uses the same *pre-exposed* imported-definition-drift
fixture, so no result here constitutes independent predictive accuracy.

## Motivation and implemented mechanism

Prior Lean support probes used `toString (repr nativeExpr)` to fingerprint
types and declaration values. Those representations are diagnostics and
their formatting is not an explicitly defined serialized kernel AST.

The new `experiments/rtk/lean_structural_expr_probe_v1.lean.txt` traverses
native `Lean.Expr`, `Lean.Level` and `Lean.Name` constructors and emits a
JSON syntax tree. The controlled constructor set includes de Bruijn
variables, sorts and universe parameters/successors/max/imax,
declaration constants with exact universe instantiation lists,
applications, lambdas, dependent arrows, let expressions,
natural/string literals, projections and binder annotations.

`Name` is encoded structurally, distinguishing string and numeric name
components rather than relying on a possibly ambiguous display string.

The implementation rejects free variables, expression or level metavariables,
expression metadata, unknown constructors and excessive recursion.
**No unsupported node is omitted or silently replaced with `Expr.repr`.**
The companion parser
`experiments/rtk/lean_structural_expr_v1.py` recursively checks JSON shape,
constructor arity, reference fields, resource bounds and subject identity.

The parser records SHA-256 fingerprints of the *canonical JSON encoding*
of (i) the source theorem statement Expr, (ii) the source historical checked
theorem proof Expr, (iii) imported `op` type Expr on both sides, and
(iv) imported `op` declaration value Expr on both sides.

The native workflow
`.github/workflows/rtk-lean-structural-expr-v1.yml` runs under two
separately installed, SHA-256-pinned Lean 4.14.0 toolchains. The source
contains the actual historical proof term. The target includes only the
unproved `rtk_unproven_target_claim` axiom goal placeholder.
The workflow executes the pre-existing imported-module drift and
proof-reference checks *before* structural extraction. It **does not**
execute the historical proof or fresh target proof against the target.

Expected (unconfirmed until CI) structural observations are exact source
and target statement AST identity, equal `op` types and changed `op`
definition values under a same-name imported module. All outcomes remain
`UNDETERMINED` for transport applicability.

## Important semantics and source grounding

Lean 4.14.0 at `leanprover/lean4` commit
`410fab7284703f41660ca2454218dcca9b2ec896` defines `Expr` and
`BinderInfo` in `src/Lean/Expr.lean` (Git blob
`a226a39df108d3282a7b88b80695e9306acb3470`) and `Level` in
`src/Lean/Level.lean` (Git blob
`393b5f431b82b55a2917ddc234591678f6417645`).
Those are the native constructors targeted by the serializer.
This is **source-grounded implementation**, not an external verification
of encoder correctness.

The encoding preserves the included constructors of native expressions
as a versioned JSON AST, but there is no independently validated Lean
decoder, roundtrip kernel checker, expression alpha-equivalence theorem,
normalization theorem, or proof that every semantically material
dependency is present. Lean metadata nodes are conservatively rejected.
The source theorem may have imported axiom and computational dependencies
outside the examined `op` declaration. Capturing individual ASTs does not
establish their transitive closure, imported-module semantical completeness,
kernel soundness, or authority of any signed record.

Fingerprints bind *declared structural bytes within this restricted
encoder*, not generalized proof certificates. A source/target matching AST
does not by itself mean that the historical evidence is valid. The tool
permanently records:

- `target_claim_established=false`
- `target_historical_proof_replayed=false`
- `cross_environment_semantic_completeness_proved=false`
- `serialized_expr_deserialization_kernel_checked=false`
- `native_ast_log_provenance_authenticated=false`
- `transport_applicability=UNDETERMINED`

## Follow-on acceptance gate

Implement a self-contained **native decoder and checked roundtrip** for
this constructor fragment, explicitly preserving universe instantiations,
binder annotations and declaration subject identity. Then bind the ASTs
to complete, independently authenticated transitive module/declaration
and trust-policy context, with independent source/target checker
provenance. Keep the SUT's prospective predictions sealed before any
historical target replay or native target result is accessed.

The positive development result in #188 is already exposed and remains
excluded from any confirmatory corpus.
