# Infrastructure Normalization Hooks

OVK's infrastructure exposure checker consumes a normalized infrastructure abstraction. Sprint 4 adds parser hooks that produce that abstraction from narrower source formats.

## Unified normalizer

Module:

```text
ovk.adapters.infra.normalize
```

Supported input formats:

- `infra`: native OVK infrastructure abstraction.
- `terraform`: Terraform-plan-style JSON subset.
- `kubernetes`: Kubernetes Service-style JSON subset.

The infrastructure runner accepts the same formats through `--input-format`.

## Terraform-plan-style hook

Module:

```text
ovk.adapters.infra.tf_plan
```

Purpose:

- Convert a small Terraform-plan-style JSON subset into OVK infrastructure input.
- Read sensitivity from resource fields or tags.
- Read public exposure from explicit booleans, public ACL values, public policy flags, and internet-accessible flags.

## Kubernetes-style hook

Module:

```text
ovk.adapters.infra.k8s
```

Purpose:

- Convert Kubernetes Service-like resources into OVK infrastructure input.
- Read sensitivity from annotations.
- Read public exposure from service type and explicit OVK annotations.

## Safety rule

Parser hooks are narrow by design. Unsupported or empty normalization results become invalid infrastructure abstractions, which the evidence layer maps to `unknown` and `require_human_review`.
