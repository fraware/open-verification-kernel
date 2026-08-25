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
MergePolicy(I, EvidenceSet) -> DecisionState
```

Normative ``DecisionState`` lattice:

```text
allow
block
needs_review
unknown
error
skipped
```

Checker claim statuses remain distinct:

```text
pass | fail | unknown | error | skipped
```

``merge_recommendation`` is a deprecated alias of ``decision_state``
(``needs_review`` ↔ ``require_human_review``). Legacy values
``allow_with_warning`` and ``require_stronger_check`` are not lattice
members; they map onto ``needs_review`` (never onto ``allow``).

Hard rules:

```text
error never promotes to allow          (strict and advisory)
unknown never becomes allow in strict  (advisory preserves unknown)
required skipped never silent-allows   (strict: skipped or block)
advisory preserves original_decision_state
decision lists controlling_finding_ids[] and finding_contributions[]
```

Default strict logic:

```text
if any required claim fails:
    block
elif any required claim is error:
    error
elif any required claim is unknown:
    needs_review or block   # per default_on_unknown; never allow
elif any required claim is skipped:
    skipped or block        # per default_on_required_skip; never allow
elif all required claims pass:
    allow
else:
    needs_review
```

Advisory mode keeps the honest lattice member in ``decision_state`` /
``original_decision_state`` and does not invent ``allow_with_warning``
as a lattice value; non-blocking behavior is an exit-code / CI concern.

## Security rules

These match the rules in [THREAT_MODEL.md](THREAT_MODEL.md): agents cannot self-disable checks; unknowns never pass in strict mode; evidence is complete and content-addressed; critical failures block unless a human override is recorded; high-risk runtime checks need template provenance or human review.

## Minimal TLA+ decision model

```tla
--------------------------- MODULE OVKDecision ---------------------------
EXTENDS Naturals, Sequences

CONSTANTS Intents, Critical, Pass, Fail, Unknown, Error, Skipped
CONSTANTS Allow, Block, NeedsReview, DecisionUnknown, DecisionError, DecisionSkipped

VARIABLES result, decision

Init ==
  /\ result \in [Intents -> {Pass, Fail, Unknown, Error, Skipped}]
  /\ decision = NeedsReview

CriticalFailure ==
  \E i \in Critical : result[i] = Fail

CriticalError ==
  \E i \in Critical : result[i] = Error

CriticalUnknown ==
  \E i \in Critical : result[i] = Unknown

CriticalSkipped ==
  \E i \in Critical : result[i] = Skipped

AllRequiredPass ==
  \A i \in Critical : result[i] = Pass

Decide ==
  IF CriticalFailure THEN
    decision' = Block
  ELSE IF CriticalError THEN
    decision' = DecisionError
  ELSE IF CriticalUnknown THEN
    decision' = NeedsReview
  ELSE IF CriticalSkipped THEN
    decision' = DecisionSkipped
  ELSE IF AllRequiredPass THEN
    decision' = Allow
  ELSE
    decision' = NeedsReview

Safety_NoAllowOnCriticalFail ==
  CriticalFailure => decision # Allow

Safety_NoAllowOnCriticalError ==
  CriticalError => decision # Allow

Safety_NoAllowOnCriticalUnknown ==
  CriticalUnknown => decision # Allow

Safety_NoAllowOnCriticalSkipped ==
  CriticalSkipped => decision # Allow
=============================================================================
```
