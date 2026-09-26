# Protected Effect Integrity evaluation v1

The structural compiler identifies obligations. The evaluation layer composes
those obligations with backend evidence and produces a three-valued semantic
result for each protected effect.

## Outcomes

PASS requires all of the following:

- source extraction coverage is complete;
- a protected semantic path is represented;
- a compatible authorization guard exists;
- principal binding is established;
- effect binding is established;
- resource binding is established.

FAIL requires a concrete violated dimension. A known violation is not hidden by
partial extraction coverage.

UNKNOWN is returned when no violation is established and either extraction
coverage is incomplete or some proof obligation lacks sufficient evidence.

## Alternative authorization guards

Multiple candidate guards are treated disjunctively for resource binding.

- any established candidate binding is sufficient;
- all candidate bindings refuted means violation;
- no established binding plus at least one unresolved binding means unknown.

This matches the semantic question: at least one valid authorization decision for
the principal/effect/resource triple is sufficient to justify the protected
effect.

## Trust boundary

The evaluator composes evidence; it does not erase assumptions.

A PASS remains conditional on:

1. the source profile faithfully representing the supported program semantics;
2. declared guard, sink, loader identity, and loader scope semantics;
3. backend correctness for the discharged obligations.

The evaluation object records the Assurance IR digest, extraction coverage,
checks, resource-binding evidence, and assumptions so later attestation layers
can bind the result to the exact semantic model.
