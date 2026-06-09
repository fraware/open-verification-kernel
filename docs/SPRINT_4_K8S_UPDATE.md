# Sprint 4 Kubernetes Normalization Update

The infrastructure exposure path now includes a Kubernetes-style normalization hook.

Implemented:

- Added `ovk.adapters.infra.k8s`.
- Converts Service resources into OVK infrastructure input.
- Detects sensitivity from annotations.
- Detects public exposure from Service type and explicit OVK annotations.
- Added Kubernetes normalization tests.

Current limitation:

The hook intentionally supports a narrow manifest subset. It is a normalization layer for service exposure, not a complete Kubernetes parser.
