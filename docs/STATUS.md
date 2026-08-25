# OVK Status

Generated from `.verification/project-status.json` (candidate `58bee916492f7aa4f550ea6ced9f7271f065656e`).

Do not hand-edit this file. Regenerate with `python scripts/build_project_status.py`.
Adoption and pin guidance: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Maturity

Normative field: `conformance_status_v3`. `production_status` is legacy catalog metadata only.
Local `source_profile_strict_eligible` is not `externally_calibrated_strict`.
FormalPR-Bench is regression-only; `verified_source_sha` requires the release ledger.

## Profile statuses

- `authorization.express.ast_v1`: source_profile_strict_eligible (contract 1.1.0, strict_ready=True)
- `authorization.fastapi.ast_v1`: source_profile_strict_eligible (contract 1.0.0, strict_ready=True)
- `ci_secrets.actions.permissions_flow_v1`: source_profile_strict_eligible (contract 1.0.0, strict_ready=True)
- `deployment.trusted_profile_v1`: source_profile_strict_eligible (contract 1.0.0, strict_ready=True)
- `infrastructure.kubernetes.controller_reachability_v1`: source_profile_strict_eligible (contract 1.0.0, strict_ready=True)
- `infrastructure.terraform.plan_recursive_v1`: source_profile_strict_eligible (contract 1.0.0, strict_ready=True)

## Open blockers

- verified_source_sha deferred to WP-17 release ledger
- externally_calibrated_strict not claimed
