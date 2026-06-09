# Sprint 4 Regression Update

The infrastructure exposure path now generates regression artifacts.

Implemented:

- Added `ovk.adapters.infra.regression`.
- Added regression rendering for infrastructure exposure counterexamples.
- Updated `ovk.adapters.infra.evidence` to attach generated regression tests when public sensitive resources are found.
- Added tests for regression rendering.
- Added tests for evidence-level regression artifact attachment.

Generated artifact path:

```text
.verification/generated_tests/test_no_public_sensitive_resource.py
```

Safety rule:

Regression artifacts are emitted only when concrete exposure counterexamples exist. Invalid abstractions remain unknown and require review.
