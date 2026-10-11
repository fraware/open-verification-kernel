# Lean 4 proof-term replay — prospective v2 development control

**Status:** synthetic, pre-outcome development demonstration. This is the
first native checker adapter for the RTK research pipeline. The fixture does
not derive from an independently selected historical production repository,
does not assess OVK's external validity, and is **not a confirmatory sample**.

## Checker and historical evidence

- Native checker: Lean 4.14.0, executed as a separate subprocess without
  importing RTK predictions or OVK's evidence-reuse classifier.
- Bootstrap: elan v4.2.3 release tarball, checked against SHA-256
  `df0b2b3a439961ffcbb3985214365ffe40f49bc871df04dff268c7d8e21ca8b2`.
  This bootstrap digest was independently published by Lean maintainers in
  their `lean-eval-submissions` historical replay build instructions.
- Lean toolchain: fixed release `leanprover/lean4:v4.14.0`. The first
  workflow version verifies reported Lean version and records a binary
  checksum, yet does not compare its archive against an independently fixed
  expected hash. Binary provenance is a documented remaining limitation.
- Exact historical evidence: the bytes of
  `lean_replay_fixtures_v2/historical_proof.term.txt`,
  containing the Lean proof term `Eq.refl n`.
- Source declaration: `theorem historical_claim (n : Nat) : n + 0 = n :=`.
  Lean's definitional reduction accepts the historical term under the
  fixed checker.
- Irrelevant target change: the same theorem plus an unrelated comment.
  The same unchanged proof term is submitted to Lean.
- Relevant target change: `theorem historical_claim (n : Nat) : 0 + n = n :=`.
  The exact same old proof term is submitted first, separately from any
  newly produced proof.
- Fresh target proof: `Nat.zero_add n`, compiled in a **separate** native
  execution. A successful fresh proof establishes a true changed target
  theorem without establishing validity of the historical `Eq.refl n` term.

These declarations are logically related, but kernel definitional equality
is stricter than logical equivalence. The pilot intentionally probes that
difference. It is *term-source replay*, not replay of a serialized Lean
kernel expression or independently checked proof certificate format.

## Procedure

Run the dedicated workflow at
`.github/workflows/rtk-lean-proofterm-replay-v2.yml`, or from a machine with
the pinned Lean toolchain installed:

```bash
FIX=experiments/rtk/lean_replay_fixtures_v2
python experiments/rtk/native_lean_replay_v2.py \
  --lean "$HOME/.elan/bin/lean" \
  --source "$FIX/source_declaration.lean.txt" \
  --target "$FIX/target_unchanged_declaration.lean.txt" \
  --evidence "$FIX/historical_proof.term.txt" \
  --output unchanged.json

python experiments/rtk/native_lean_replay_v2.py \
  --lean "$HOME/.elan/bin/lean" \
  --source "$FIX/source_declaration.lean.txt" \
  --target "$FIX/target_changed_declaration.lean.txt" \
  --evidence "$FIX/historical_proof.term.txt" \
  --fresh "$FIX/fresh_target_proof.term.txt" \
  --output changed.json
```

All inputs are committed independently; original proof bytes are reused
verbatim. The runner records SHA-256 identities of the source declaration,
target declaration, original term and exact composed verifier inputs, plus
checker output/diagnostic digests and exit codes.

## What counts as an observation

- **Source accepted:** the exact old term checks against the source theorem.
- **Historical admissibility, supported:** the exact old term checks
  against the exact target theorem under the same pinned Lean checker.
- **Historical inapplicability, supported for this narrow fixture:** the old
  term is source-accepted, then Lean rejects it on the target with a recorded
  *type-mismatch diagnostic*. This does not entail false target theorem.
- **Target established:** an independently provided fresh proof term is
  accepted by Lean for the changed target.
- **Unresolved:** unavailable/wrong checker, timeout, source failure,
  unrecognized target rejection, or any other insufficient observation.
  Missing data never becomes historical invalidity or a target refutation.

The native checker output, invocation and bytes need independent archival
review before any results are called reproducible; a passing CI badge alone
is insufficient. A human reviewer must inspect the exact statement and
the diagnostics. In particular, matching a substring in a diagnostic is a
fixture-specific rule, not a general certificate-rejection adjudicator.

## Limits

The adapter has **no power to prove** arbitrary Lean theory continuity,
reliance-policy admissibility, repository revision correspondence or
software-authorization behavior. It assumes the trusted Lean kernel and
the native term checker are appropriate authorities for this fixture.
It does not formalize RTK soundness or demonstrate cost savings.

The unit tests use a simulated checker exclusively for CLI and fail-closed
plumbing; such results must never be reported as independent Lean evidence.
The dedicated native workflow is the only automated source of native
results here.

This is a **development** control for issue #177, not an external corpus or
preregistered v2 evaluation. No outcomes have been used to update v1
qualification rules. The next research step is to adapt the same procedure
to historical source/target claims selected independently of OVK's prediction.
