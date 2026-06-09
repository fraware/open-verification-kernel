# Sprint 3 Status

Sprint 3 focuses on turning the authorization path into a real SMT-backed architecture.

## Goal

Move the authorization example from a fixture-level reachability checker toward a structured proof-obligation pipeline with explicit query polarity, obligation serialization, solver-independent planning, counterexample translation, and regression artifact generation.

## Completed so far

- Added `ovk.adapters.z3.obligation`.
- Added `AuthorizationObligation`, `AuthorizationRoute`, and `RouteReachabilityWitness`.
- Added explicit query polarity through `find_violation`.
- Added `obligation_to_dict` for diagnostics and evidence attachment.
- Added `ovk.adapters.z3.counterexample`.
- Added deterministic obligation-to-counterexample translation that preserves obligation ID and query polarity.
- Added `ovk.adapters.z3.smt_plan`.
- Added a solver-independent `SmtPlan` and `SmtClause` representation.
- Added `ovk.adapters.z3.regression`.
- Added pytest regression artifact rendering from authorization counterexamples.
- Added tests for obligation construction, serialization, counterexample translation, SMT plan generation, and regression artifact rendering.

## Current architecture

```text
authorization fixture
→ AuthorizationObligation
→ solver-independent SmtPlan
→ counterexample translation
→ regression artifact generation
→ future Z3 executor
```

## Current limitation

The high-level authorization evidence adapter has not yet been replaced with the obligation-backed adapter. Connector safety controls blocked the full adapter replacement in this pass. The lower-level obligation, SMT-plan, counterexample, and regression modules are present and tested, so engineers can wire them into the existing adapter manually or in a later connector-safe patch.

## Remaining Sprint 3 work

1. Wire the existing authorization adapter through the obligation model.
2. Add a Z3 executor that consumes `AuthorizationObligation` or `SmtPlan`.
3. Map Z3 `sat`, `unsat`, and `unknown` into OVK evidence.
4. Record query polarity and solver model in counterexamples.
5. Attach generated regression tests to authorization evidence.
6. Add optional integration tests that run only when `z3-solver` is installed.

## Engineering rule

The authorization backend must preserve query polarity. A satisfiable violation query means a counterexample exists. An unknown solver result must require human review and must not become a pass.
