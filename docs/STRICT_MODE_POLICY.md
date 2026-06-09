# Strict Mode Policy

This document defines the current strict-mode policy for the self-protection path.

## Decision

For v0, strict mode uses the deterministic self-protection evaluator as the authoritative decision path.

The optional OPA CLI runner is supplementary. It may strengthen diagnostics and future evidence, but strict mode must not depend on the presence of the OPA binary until OPA parity is tested across the benchmark suite and installation behavior is stable.

## Rationale

The deterministic evaluator is the fixture oracle. It is available in every installation, runs without external binaries, and already implements the conservative evidence rule:

- concrete self-protection failure returns `block`;
- missing required-check metadata returns `require_human_review`;
- clean evidence returns `allow`.

The OPA CLI path is valuable, but it introduces an external dependency. Missing binaries, invalid output, or timeouts must never become a pass. Treating OPA as mandatory before installation behavior is mature would make early strict mode fragile.

## Current v0 strict behavior

| Condition | Result |
|---|---|
| Deterministic evaluator returns fail | `block` |
| Deterministic evaluator returns unknown | `require_human_review` |
| Deterministic evaluator returns pass | `allow` |
| OPA binary unavailable | does not weaken deterministic result |
| OPA returns fail in supplemental run | future policy should escalate to `block` or `require_human_review` after parity integration |

## Future policy

Once OPA parity is validated, OVK should support a backend strategy option:

```text
deterministic
opa
both
```

Recommended future semantics:

- `deterministic`: current default v0 behavior;
- `opa`: require OPA and return unknown when unavailable;
- `both`: fail dominates; unknown from a required backend returns human review; pass requires all required backends to pass.

## Engineering rule

Strict mode must be predictable. It should never depend on an optional backend unless the user explicitly selects that backend as required.
