# Sprint 3 Status

Sprint 3 focuses on turning the authorization path into a real SMT-backed architecture.

## Goal

Move the authorization example from a fixture-level reachability checker toward a structured proof-obligation pipeline with explicit query polarity, obligation serialization, solver-independent planning, counterexample translation, regression artifact generation, optional Z3 execution, normalized solver-result semantics, first-class OVK evidence construction, and input-validation discipline.

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
- Added `ovk.adapters.z3.evidence`.
- Added first-class `VerificationEvidence` construction from normalized Z3 authorization results.
- Added generated regression artifacts to authorization evidence when counterexamples exist.
- Added `ovk.adapters.z3.validation` and `ovk.adapters.z3.validation_evidence`.
- Added `ovk.adapters.z3.validated_path`.
- Updated the authorization runner to use the validated path.
- Added tests for obligation construction, serialization, counterexample translation, SMT plan generation, regression artifact rendering, optional Z3 execution, result normalization, evidence construction, validation behavior, and malformed-input runner behavior.

## Current architecture

```text
authorization fixture
→ validation
→ AuthorizationObligation
→ optional Z3 executor
→ normalized solver result
→ VerificationEvidence
→ evidence bundle
→ Markdown report
→ unsigned attestation statement
```

## Current limitation

The existing stable authorization adapter has not yet been replaced with the obligation-backed path. The obligation-backed path now exists as a validated runner and tested lower-level modules, so it can be exercised without replacing the stable adapter.

## Remaining Sprint 3 work

1. Add a first-class `ovk` CLI command for the authorization runner.
2. Optionally wire the existing authorization adapter through the obligation-backed path once safe to patch.
3. Wire the authorization obligation scorer into CI when workflow edits are permitted.
4. Add more adversarial malformed-input benchmark cases.
5. Add direct package-level runner utilities if connector controls permit them.

## Engineering rule

The authorization backend must preserve query polarity. A satisfiable violation query means a counterexample exists. An unknown solver result or invalid route abstraction must require human review and must not become a pass.
