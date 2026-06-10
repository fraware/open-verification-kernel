# OVK Router Policy Recipes

Use `.verification/config.yml` to tune routing strictness, runtime budget, and backend allow/deny controls.

Schema: `schemas/verification.config.schema.json`.

Reference behavior check: `tests/test_phase2_kernel.py` (`test_budget_from_policy_denies_expensive_backends`).

## Recipe 1: Advisory OSS default

Use this for initial rollout where OVK should provide signals but not break contributor flow.

```yaml
schema_version: ovk.config.v1
mode: advisory
default_on_unknown: require_human_review
budget:
  max_wall_time_seconds: 30
  max_memory_mb: 512
  allowed_backends: [opa, z3, cedar]
  denied_backends: []
routing:
  prefer_deterministic: false
```

Expected router behavior: routes to compatible backends, allows unknowns to degrade to human review.

## Recipe 2: Strict production

Use this in protected branches where ambiguous outcomes must block merge.

```yaml
schema_version: ovk.config.v1
mode: strict
default_on_unknown: block
budget:
  max_wall_time_seconds: 60
  max_memory_mb: 768
  allowed_backends: [opa, z3, cedar, cbmc, alloy]
  denied_backends: [dafny, lean, verus]
routing:
  prefer_deterministic: true
```

Expected router behavior: expensive assistants are excluded; unknown outcomes are blocking.

## Recipe 3: Deterministic-only CI

Use this when CI predictability and runtime consistency are higher priority than exhaustive proving.

```yaml
schema_version: ovk.config.v1
mode: strict
default_on_unknown: block
budget:
  max_wall_time_seconds: 25
  max_memory_mb: 384
  denied_backends: [dafny, verus, lean, kani]
routing:
  prefer_deterministic: true
```

Expected router behavior: proof-assistant backends are rejected by budget policy; deterministic and lightweight engines dominate.

## Recipe 4: Security-sensitive bot PRs

Use this for automation-authored changes where fast, high-signal checks should gate merges.

```yaml
schema_version: ovk.config.v1
mode: strict
default_on_unknown: require_human_review
budget:
  max_wall_time_seconds: 15
  max_memory_mb: 256
  allowed_backends: [opa, z3, cedar]
  denied_backends: [dafny, lean, verus, kani]
routing:
  prefer_deterministic: true
```

Expected router behavior: only security-focused engines are considered, and unrecognized situations require manual reviewer sign-off.

## Recipe 5: Full formal stack

Use this for deep validation windows (nightly or release candidate verification) where longer execution is acceptable.

```yaml
schema_version: ovk.config.v1
mode: strict
default_on_unknown: require_human_review
budget:
  max_wall_time_seconds: 300
  max_memory_mb: 2048
  denied_backends: []
routing:
  prefer_deterministic: false
```

Expected router behavior: broad backend coverage, including higher-cost formal engines.
