# Patched Lean 4.35.0 semantic-drift development control

This is **source-text replay**, not replay of the historical serialized Lean `Expr`. The separate 4.35.0 toolchain builds fresh imported module files in isolated source, equal-target and changed-target directories.

- `op n := n` in the source and equal context; `op n := 0 + n` in the changed target.
- The same historical proof **source text** `theorem historical_claim (n : Nat) : op n = n := Eq.refl n` must compile under `lean --trust=0` in the source and equal context.
- That same text must be rejected under the changed definition; a separate fresh proof using `Nat.zero_add` must compile.
- The workflow retains native compilation logs, case-specific .olean/source hashes, a versioned no-reliance record, and still runs sandboxed `lake check --paranoid` against the clean smoke theorem.

## Nonclaims

These controls are **not** exact historical certificate transport. Elaboration from source syntax is distinct from rechecking the serialized historical proof AST under a new environment. The new version also does not establish the full kernel support theorem, independent authenticated provenance, or authorized reliance. The original Lean 4.14 artifacts are never copied into the patched toolchain. The changed target's fresh proof must not contaminate the historical-replay verdict.

Complete the 4.35-native structural `Expr` export, exact source-proof digest binding and independent target-kernel replay before claiming any historical certificate admissibility. Both the current repository's main guarantee and a prospective production `VALID` remain unauthorized. Related issues #205, #195 and #177. Keep draft/unmerged.
