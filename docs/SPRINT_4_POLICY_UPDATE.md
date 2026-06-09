# Sprint 4 Policy Update

The infrastructure exposure checker now uses an explicit policy object.

Implemented:

- Added `ovk.adapters.infra.policy`.
- Added `InfraExposurePolicy`.
- Added `DEFAULT_INFRA_EXPOSURE_POLICY`.
- Routed `ovk.adapters.infra.exposure.find_exposure_counterexamples` through the policy object.
- Added tests for default and custom policy behavior.

Default policy:

- public exposure of confidential resources is blocked;
- public exposure of restricted resources is blocked;
- internal resources are allowed to be public by default.

Custom policies can choose a stricter set of blocked sensitivity levels.
