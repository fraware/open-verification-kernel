# Sprint 4 Policy Configuration Update

Infrastructure exposure policy is now configurable from JSON.

Implemented:

- Added `ovk.adapters.infra.policy_config`.
- `evaluate_infra_exposure` accepts an explicit policy object.
- `scripts/run_infra_exposure.py` accepts `--policy`.
- Added policy-loader tests.
- Added runner-level policy tests.

Policy shape:

```json
{
  "blocked_public_sensitivities": ["internal", "confidential", "restricted"]
}
```

Default behavior blocks public exposure for confidential and restricted resources. A stricter policy can also block internal resources.
