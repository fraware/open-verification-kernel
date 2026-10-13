# Patched Lean 4.35.0 multi-checker smoke — research v1

**Security gate:** [#205](https://github.com/fraware/open-verification-kernel/issues/205). This workflow exists separately from the archived Lean 4.14.0 semantic-drift research sequence, because **Lean 4.14 is affected by a publicly reported kernel soundness defect** even under `--trust=0`.

## Upstream source

The official [Lean 4.32.2 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.32.2/) document the July 2026 kernel soundness fix. The [upstream incident #14576](https://github.com/leanprover/lean4/issues/14576) and [August 2026 advisory](https://www.openwall.com/lists/oss-security/2026/08/02/1) identify vulnerable releases through 4.31.0, including the pinned v4.14.0. An invalid axiom-free proof can exploit the bug even with the trust-zero flag.

The [Lean 4.35.0 release notes of October 12, 2026](https://lean-lang.org/doc/reference/latest/releases/v4.35.0/) introduce `lake check` and `lake check --paranoid`, including sandboxed project creation/export and several bundled alternative checkers. These provide stronger independent operational evidence than repeatedly replaying a certificate with only an affected historical kernel.

## Strict boundary of the new workflow

`.github/workflows/rtk-lean-patched-independent-check-smoke-v1.yml` installs **Lean 4.35.0** by exact version. It creates a **new** minimal Lake project under a temporary directory using source text, defines `op n := n`, checks a source theorem `op n = n` and builds the corresponding new `.olean` from scratch. It then runs `lake check --paranoid` and must fail if that tool fails. Native version/build logs, recompiled module SHA and checker command transcript are retained as research artifacts. It never copies the v4.14.0 `.olean` file into the patched environment.

This is deliberately a **patched-checker infrastructure smoke**, not a migration of the historical serialized Lean 4.14 proof expression, not transport across an altered definition, and not a measurement of a held-out false-reuse rate. Any failure during installation, sandbox startup, export, checker availability, axiom policy or memory/time budgets must be reported as a failure. Do not skip an unavailable checker and claim the full set passed.

## Future actual qualification gates

1. Audit and pin the Lean 4.35 executable bytes and supported checker invocations by SHA, not just the human-readable version string.
2. Build the *full* source/target imported-module and historical proof fixtures natively under 4.35. Export and bind the *newly serialized* historical certificate and exact target proposition to their source contexts. Reuse the old 4.14 results only as version-labelled historical comparisons.
3. Independently check the source theorem and complete imported context, distinguish its admitted axioms, then adjudicate the exact old proof against the new target context. Treat the **checker version upgrade itself as a context change** requiring revalidation.
4. Separately prove a sufficient kernel-context preservation relation and extractor adequacy, authenticate relying policies, enforce revocation/expiry, and execute the prospective protocol #177.
5. No security-relevant `VALID` or production authorization before all relevant gates are met and independently reviewed.

The independent checkers and sandbox reduce attack surface but do **not** by themselves establish an abstract theorem of kernel correctness. The experiment never claims that a smoke-test success establishes general certificate transport.
