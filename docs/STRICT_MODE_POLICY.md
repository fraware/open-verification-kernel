# Strict Mode Policy

This document defines the current strict-mode policy for the self-protection path.

## Decision

For v0, strict mode uses the deterministic self-protection evaluator as the default authoritative decision path.

The optional OPA CLI runner is available through the `backend-strategy` option, but strict mode does not depend on OPA unless the user explicitly selects `opa` or `both`.

## Rationale

The deterministic evaluator is the fixture oracle. It is available in every installation, runs without external binaries, and already implements the conservative evidence rule:

- concrete self-protection failure returns `block`;
- missing required-check metadata returns `require_human_review`;
- clean evidence returns `allow`.

The OPA CLI path is valuable, but it introduces an external dependency. Missing binaries, invalid output, or timeouts must never become a pass.

## Backend strategies

OVK now supports three self-protection backend strategies:

| Strategy | Meaning |
|---|---|
| `deterministic` | Use the deterministic evaluator only. This is the v0 default. |
| `opa` | Use optional OPA policy evaluation only. Missing OPA returns unknown. |
| `both` | Run deterministic and optional OPA paths. Bundle semantics apply fail and unknown dominance. |

## Current v0 strict behavior

| Condition | Result |
|---|---|
| Deterministic evaluator returns fail | `block` |
| Deterministic evaluator returns unknown | `require_human_review` |
| Deterministic evaluator returns pass | `allow` |
| `backend-strategy=opa` and OPA unavailable | `require_human_review` |
| `backend-strategy=both` and deterministic fails | `block` |
| `backend-strategy=both` and any required path is unknown | `require_human_review`, unless another path fails |

## Recommended configuration

Use the default strategy for first installation:

```bash
ovk ci --backend-strategy deterministic
```

Use OPA for local or hardened installations where the OPA binary is installed and parity has been checked:

```bash
ovk ci --backend-strategy opa
```

Use both paths when testing backend parity:

```bash
ovk ci --backend-strategy both
```

## Engineering rule

Strict mode must be predictable. It should never depend on an optional backend unless the user explicitly selects that backend as required.
