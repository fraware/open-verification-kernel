# Sprint 4 Input Format Update

Infrastructure exposure now has a unified input normalization layer.

Implemented:

- Added `ovk.adapters.infra.normalize`.
- Supported formats are `infra`, `terraform`, and `kubernetes`.
- Updated `scripts/run_infra_exposure.py` with `--input-format`.
- Added tests for native, Terraform-style, and Kubernetes-style input normalization.
- Added runner tests for all supported input formats.
- Updated `docs/INFRASTRUCTURE_NORMALIZATION_HOOKS.md`.

Current CLI status:

The standalone runner supports multiple input formats. The first-class `ovk infra-exposure` CLI command still accepts native OVK infrastructure input only. The CLI patch to add `--input-format` was blocked by connector controls.
