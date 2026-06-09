# Sprint 4 Terraform Plan Update

The infrastructure exposure path now includes a Terraform-plan-style normalization hook.

Implemented:

- Added `ovk.adapters.infra.tf_plan`.
- Converts a small supported subset of Terraform-plan-style JSON into OVK infrastructure input.
- Detects sensitivity from resource fields or tags.
- Detects public exposure from explicit booleans, public ACL values, public policy flags, or internet-accessible flags.
- Added `tests/test_infra_tf_plan.py`.

Current limitation:

The normalizer is intentionally narrow. It does not claim full Terraform support and should be treated as a parser hook for plan-derived abstractions.
