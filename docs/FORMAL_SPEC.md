# Formal Specification

This document defines OVK's formal verification semantics. It is intentionally modest. OVK does not claim to verify all software. It makes verification claims explicit, routed, and auditable.

## Repository state and change

Let:

```text
S_before = repository state before the change
S_after  = repository state after the change
Δ        = S_after - S_before
A        = actor metadata
C        = repository context
```

A change is:

```text
χ = (S_before, S_after, Δ, A, C)
```

The intent engine computes:

```text
InferIntents(χ) -> {I_1, I_2, ..., I_n}
```

## Verification intent

A verification intent is:

```text
I = (scope, actor, operation, property, failure_modes, acceptable_evidence, merge_policy)
```

Supported property kinds today:

| Kind | Meaning |
|---|---|
| safety | Bad state must be unreachable |
| invariant | Condition must be preserved across change |
| access_control | Forbidden actor cannot perform operation |
| data_boundary | Restricted data/resource cannot flow to forbidden sink |
| forbidden_configuration | Disallowed configuration must not appear |

Deferred property kinds:

| Kind | Reason deferred |
|---|---|
| liveness | Requires careful backend and model assumptions |
| equivalence | Expensive and domain-specific |
| refinement | Requires stronger formal modeling |
| runtime_monitorable | Requires runtime enforcement compiler |

## Backend capability

A backend is:

```text
B = (domains, property_kinds, input_languages, guarantee_type, compile, run, normalize)
```

Each backend provides:

```text
CanHandle(B, I, C) -> score in [0, 1]
Compile(B, I, C, χ) -> Obligation
Run(B, Obligation) -> RawResult
Normalize(B, RawResult) -> VerificationResult
```

## Backend selection

OVK selects backends by practical utility.

```text
Utility(B, I, C, budget) =
    α * relevance
  + β * guarantee_strength
  + γ * historical_success
  - δ * cost
  - ε * runtime
  - ζ * integration_risk
```

The first implementation can use rule-based scoring. Later implementations may learn from repository history.

## Result semantics

Every backend result must normalize to:

```text
Pass(evidence, assumptions, bounds)
Fail(counterexample, violated_property)
Unknown(reason)
Error(system_failure)
Skipped(justification)
```

Interpretation:

- `pass` means no violation was found under the stated semantics, assumptions, and bounds.
- `fail` means a concrete violation, model, trace, policy violation, or proof failure was found.
- `unknown` means the backend could not decide within budget or lacked context.
- `error` means tool or adapter failure.
- `skipped` means OVK intentionally did not run the backend and recorded why.

## Evidence validity

An evidence claim is valid only if it is traceable to an intent, obligation, backend capability manifest, tool version, input digest, result, assumptions, bounds, and decision policy.

```text
ValidEvidence(E) iff
  exists I, O, B, R such that
    E.intent_id = I.intent_id
    O = Compile(B, I, C, χ)
    R = Normalize(B, Run(B, O))
    E.result summarizes R
    E.assumptions include B.assumptions
    E.subject.hashes match χ
```

## Merge decision

```text
MergePolicy(I, EvidenceSet) -> Decision
```

Decision is one of:

```text
allow
block
require_human_review
allow_with_warning
require_stronger_check
```

Default logic:

```text
if any critical intent fails:
    block
elif any critical intent is unknown, error, or skipped:
    require_human_review
elif all required intents pass:
    allow
elif low-risk intents are skipped with justification:
    allow_with_warning
else:
    require_human_review
```

## Security rules

These match the rules in [THREAT_MODEL.md](THREAT_MODEL.md): agents cannot self-disable checks; unknowns never pass in strict mode; evidence is complete and content-addressed; critical failures block unless a human override is recorded; high-risk runtime checks need template provenance or human review.

## Minimal TLA+ decision model

```tla
--------------------------- MODULE OVKDecision ---------------------------
EXTENDS Naturals, Sequences

CONSTANTS Intents, Critical, Pass, Fail, Unknown, Error, Skipped
CONSTANTS Allow, Block, RequireHumanReview

VARIABLES result, decision

Init ==
  /\ result \in [Intents -> {Pass, Fail, Unknown, Error, Skipped}]
  /\ decision = RequireHumanReview

CriticalFailure ==
  \E i \in Critical : result[i] = Fail

CriticalUnknown ==
  \E i \in Critical : result[i] \in {Unknown, Error, Skipped}

AllRequiredPass ==
  \A i \in Critical : result[i] = Pass

Decide ==
  IF CriticalFailure THEN
    decision' = Block
  ELSE IF CriticalUnknown THEN
    decision' = RequireHumanReview
  ELSE IF AllRequiredPass THEN
    decision' = Allow
  ELSE
    decision' = RequireHumanReview

Safety_NoAllowOnCriticalFail ==
  CriticalFailure => decision # Allow

Safety_NoAllowOnCriticalUnknown ==
  CriticalUnknown => decision # Allow
=============================================================================
```
