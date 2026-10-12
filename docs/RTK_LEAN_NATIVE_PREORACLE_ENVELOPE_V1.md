# Lean pre-oracle evidence envelope — explicit incomplete transport boundary

**Status:** research development code, stacked on PR #189. This joins
the native Lean context/dependency instrumentation and structural Expr AST
evidence into one versioned record, with fail-closed cross-checks.
It is not a serialized kernel certificate, a completeness proof,
an authenticated third-party evidence bundle, or a production authorization.

## Input identity and consistency checks

`experiments/rtk/lean_native_preoracle_envelope_v1.py` accepts exactly:

- A source checked theorem and proof **native support log**.
- An unproved target-claim **native goal log**.
- Source-side and target-side native imported-reference lookup logs.
- Source-side and target-side native structural `Lean.Expr` JSON logs.
- A dual-toolchain native `.olean` comparison record, with per-module digests.
- A structural source/target expression comparison record.
- Exact historical proof *source bytes* (used only for identity).

There is **no argument accepting an oracle result**. The function refuses
extra environment record fields, truth/replay authority flags, altered
input log digests, incomplete/forged imported inventories, contradictory
module count and digest data, inconsistent source-only references,
inconsistent structural AST hashes or a target goal with a proof body.

The bridge independently recomputes the canonical SHA-256 of every
reported module-inventory record and independently derives added, removed
and changed `.olean` modules. It joins the original native checked
source proof imported constants with the target's native read-only
constant lookups. It checks both sets against the *actual list of loaded
module names reported by the native Lean processes*.

The native structural evidence is recomputed from the input native
logs using the strict Expr/Level/Name JSON constructor validator
introduced in PR #189, including the source checked proof AST.
The target goal is required to be an **unproved axiom placeholder**
with no proof expression.

The resulting development envelope includes source historical proof
*byte* SHA-256 separately from the source's checked proof *Expr AST*
SHA-256, the source and target environment module-inventory digests,
the source and target imported-definition AST digests, changed module
names, all source/target native log digests, and a conservative action.

## Decision semantics

- `REVALIDATION_REQUIRED` means an imported module, imported proof
  reference or explicitly represented structural definition changed.
  This is a conservative **recommendation for another native check**;
  byte drift alone is not evidence that the old proof is invalid.
- `UNRESOLVED` means these bounded recorded inputs have no detected
  drift. It is still **not** a VALID transport determination; the
  completeness and kernel-checking obligations are open.
- The separate `historical_evidence_applicability` field is **always
  `UNDETERMINED`**. It is never inferred from a fresh target PASS or a
  matching source/target module inventory.

The code fixes `reliance_authorization=false`,
`independent_runner_attestation_verified=false`,
`complete_semantic_support_established=false`,
`native_expr_decoder_roundtrip_verified=false`,
`source_target_policy_authenticity_verified=false`,
`prospective_holdout_case=false`,
`target_historical_proof_replay_executed=false` and
`target_claim_established=false`.

## Exact trust distinction

The bridge authenticates **internal consistency of submitted bytes and
records**, not the authenticity of the runner, the original Git commits,
Lean toolchain installation, .olean bytes claimed in a JSON manifest,
or upstream witnesses. A malicious producer able to rewrite *all*
logs and digests coherently is not defeated by these checks.
External artifact signatures, immutable Git commit ancestry, path
and checker executable digests, and independent native verification
need to be audited separately.

The structural source/target expression serializer has no independently
kernel-checked decoder. The imported `.olean` snapshot is a per-process
filesystem observation and its transitive semantics completeness is not
proved. The source and target compilers are separately installed files
from one distribution under one CI runner; independent administration
is not established.

The development case `RTKSemanticSupport` was pre-inspected in #188.
No prospective holdout or unblinded empirical accuracy measurement
is associated with this envelope.

## Executable gates

- `tests/test_rtk_lean_native_preoracle_envelope_v1.py` stresses forged
  module digests, contradictory drift, altered native logs, extra oracle
  fields, improper source/target root identity, source reference mismatch,
  target truth contamination and same-byte abstention.
- `.github/workflows/rtk-lean-native-envelope-v1.yml` runs the previous
  native Lean development controls under separately installed pinned
  Lean 4.14.0 environments, then invokes the envelope join on **actual
  native input files before any target replay step**. The full input
  logs and envelope are archived as one GitHub Actions artifact.

## Next scientific gate

A native self-contained **constructor AST decoder and checked roundtrip**
on the exact Lean 4.14 fragment, then native dependency and imported
kernel-context completeness evidence with externally authenticated source
and target module builds, followed by a versioned relation to the formal
RTK transport SUT and independently sealed prospective evaluation.

No experimental success should be described as a universal Lean
transport soundness result or an authorization of security reliance.
