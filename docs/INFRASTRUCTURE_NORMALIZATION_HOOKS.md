# Infrastructure Normalization Hooks

OVK's infrastructure exposure checker consumes a normalized infrastructure abstraction. Sprint 4 adds two narrow parser hooks that produce that abstraction.

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
