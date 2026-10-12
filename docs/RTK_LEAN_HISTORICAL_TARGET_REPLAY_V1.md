# Independent native replay of an exact historical Lean certificate (development v1)

**Scope:** bounded development fixture under pinned Lean 4.14.0, stacked on draft #194. This is a concrete step toward #195's independent historical-admissibility oracle, **not** a general transport theorem or an authorized reuse gate. The original theorem's checked proof expression is already exported, hash-bound to source evidence, and source-kernel checked by #192.

## Mechanism

The new driver `lean_historical_target_replay_v1.lean.txt` runs in a **new target-toolchain Lean invocation** with only `Lean` and target `RTKSemanticSupport` imported, plus the existing restricted native Expr encoder/decoder. It explicitly rejects preloaded `historical_claim` and `rtk_unproven_target_claim`.

The input is the **exact same serialized source proof/claim payload** from #192 and a separate target claim AST exported from an earlier *unproved target declaration* native inspection. The exporter verifies the structural claim ASTs are identical in this fixture; it does not assume that imported definitions preserve semantic meaning. The driver reconstructs the proof expression and target claim, verifies exact AST roundtrips, and calls `Lean.Kernel.check` followed by `Lean.Kernel.isDefEq` against the target claim type.

The independent Python witness validator rejects modified proof/claim ASTs, inconsistent flags, duplicate records, mismatched digests and unauthorized SUT/reliance assertions. The *native* checker (not the development expectation or RTK predictor) supplies the replay outcome.

Decisions are deliberately narrower than claim truth:

- **ADMISSIBLE**: the exact historical proof term is kernel-accepted and its inferred type definitionally equals the target claim in this designated reconstructed target kernel context.
- **INADMISSIBLE**: the exact historical proof term is kernel-accepted but its inferred type is **not** definitionally equal to the target claim. This is certificate inadmissibility, not a refutation of the proposition.
- **UNDETERMINED**: native proof checking or definitional equality returns an error or the run cannot be reliably adjudicated. Missing provenance or unexpected environment issues must not be relabeled INADMISSIBLE.

These are *development-context native replay observations*. The production policy/status is always non-controlling.

## Independent development controls

The dedicated workflow, extended in this research branch, uses two separately installed pinned Lean 4.14.0 toolchains, preserving the exact serialized source proof bytes across both target replays.

1. **Equal imported semantics:** recompile `def op (n : Nat) := n` into the target environment. Exact historical proof is expected to be admitted.
2. **Changed imported semantics:** recompile `def op (n : Nat) := 0 + n` in the same designated target installation, preserving `op` name, declaration type and the target claim AST. Exact historical proof is expected to be inadmissible.
3. **Fresh-proof counter-control:** independently check `Nat.zero_add n` as a newly provided proof of the target theorem. This proves a current target statement in the development fixture; it is **not** supplied to the replay driver or treated as historical proof reuse.
4. **Byte-level controls:** record the target `.olean` byte digest for each invocation and verify the identical source proof/claim payload and target claim payload are used in both cases.

The existing target-only axiom injection/strict reference closure experiment completes before this oracle development step. Every raw input, module byte record, native log and decision file is archived. This fixture has been inspected during development and is **excluded from future prospective accuracy estimation**.

## Trust and scientific exclusions

- The driver checks a serialized proof expression *under a reconstructed Lean target environment*. It does not establish authenticity of the historical issuer, completeness of every kernel-relevant semantic dependency, semantic adequacy of the target proposition, authenticated runner provenance, or approval by an independent relying authority.
- Current target `.olean` bytes and pinned binary digests are checked by the CI workflow, but a single hosted runner is not third-party attestation.
- Target claim AST acquisition is independently read from a native unproved target declaration. Its legitimacy as the governing target specification is an external, unresolved authority question.
- Pre-oracle applicability predictions under #184 **never consume** this target replay or fresh target proof. It is an oracle/developer experiment, not the predictor.
- `ADMISSIBLE` is conditioned on the particular kernel and context. It cannot be promoted directly to RTK `VALID` until complete claim/evidence/policy applicability premises and their refinement are justified.
- No formal theorem of support-extraction completeness, native decoder correctness, or general historical-transport soundness is proved here. No empirical false-reuse rates, costs, or savings are measured.

## Next scientific gate

For a separate precommitted confirmatory protocol under #177 and #195: fix a restrictive supported Lean fragment and authoritative context/provenance model; prove (or explicitly assume, then test) its semantic-support sufficiency; freeze source-qualified real revision histories, prediction implementation, selection and independent oracle; seal predictions before oracle adjudication; report false reuse, coverage, uncertainty and repair costs without treating the development fixtures as held-out observations.
