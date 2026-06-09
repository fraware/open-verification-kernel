# Sprint 3 Adapter Update

The stable authorization adapter now calls the validated obligation-backed path.

Implemented:

- `evaluate_authorization_reachability` delegates to the validated path.
- `find_authorization_counterexamples` uses the obligation model.
- Existing public function names remain available.
- Pull-request subject metadata is preserved.
- Added adapter compatibility tests.

Safety note:

Invalid authorization abstractions are represented as unknown evidence and require review.
