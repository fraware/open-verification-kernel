# Sprint 3 Status

Sprint 3 focuses on turning the authorization path into a real SMT-backed architecture.

## Goal

Move the authorization example from a fixture-level reachability checker toward a structured proof-obligation pipeline with explicit query polarity, obligation serialization, solver-independent planning, counterexample translation, regression artifact generation, optional Z3 execution, and normalized solver-result semantics.

## Completed so far

- Added `ovk.adapters.z3.obligation`.
- Added `AuthorizationObligation`, `AuthorizationRoute`, and `RouteReachabilityWitness`.
- Added explicit query polarity through `find_violation`.
- Added `obligation_to_dict` for diagnostics and evidence attachment.
- Added `ovk.adapters.z3.counterexample`.
- Added deterministic obligation-to-counterexample translation that preserves obligation ID and query polarity.
- Added `ovk.adapters.z3.smt_plan`.
- Added a solver-independent `SmtPlan` and `SmtClause` representation.
- Fixed SMT plan generation so it only emits non-admin violation candidates.
- Added `ovk.adapters.z3.regression`.
- Added pytest regression artifact rendering from authorization counterexamples.
- Added `ovk.adapters.z3.executor`.
- Added optional Z3 execution for `AuthorizationObligation` objects.
- Added `ovk.adapters.z3.result`.
- Added normalized result mapping for `pass`, `fail`, `unknown`, and `error`.
- Added tests for obligation construction, serialization, counterexample translation, SMT plan generation, regression artifact rendering, optional Z3 execution, and result normalization.

## Current architecture

```text
authorization fixture
→ AuthorizationObligation
→ solver-independent SmtPlan
→ optional Z3 executor
→ normalized solver result
→ counterexample translation
→ regression artifact generation
```

## Current limitation

The high-level authorization evidence adapter has not yet been replaced with the obligation-backed adapter. Connector safety controls blocked the full adapter replacement in an earlier pass. The lower-level obligation, SMT-plan, executor, result-normalization, counterexample, and regression modules are present and tested, so engineers can wire them into the existing adapter manually or in a later connector-safe patch.

## Remaining Sprint 3 work

1. Wire the existing authorization adapter through the obligation model.
2. Attach normalized Z3 results to `VerificationEvidence`.
3. Record query polarity and solver model in first-class evidence counterexamples.
4. Attach generated regression tests to authorization evidence.
5. Add an authorization CLI/demo runner for the obligation-backed path.
6. Add optional integration tests that run only when `z3-solver` is installed.

## Engineering rule

The authorization backend must preserve query polarity. A satisfiable violation query means a counterexample exists. An unknown solver result must require human review and must not become a pass.
