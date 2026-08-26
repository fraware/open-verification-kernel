# OVK Status

Generated from `.verification/project-status.json` (candidate `unknown`).

Do not hand-edit this file. Regenerate with `python scripts/build_project_status.py`.
Adoption and pin guidance: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Maturity

Normative field: `conformance_status_v3`. `production_status` is legacy catalog metadata only.
Local `source_profile_strict_eligible` is not `externally_calibrated_strict`.
FormalPR-Bench is regression-only; `verified_source_sha` requires the release ledger.
Qualification v1 is declaration-derived and cannot authorize candidate-specific maturity.

## Profile statuses

- `authorization.express.ast_v1`: executable_advisory (contract 1.1.0, strict_ready=False, candidate_bound=False)
- `authorization.fastapi.ast_v1`: executable_advisory (contract 1.0.0, strict_ready=False, candidate_bound=False)
- `ci_secrets.actions.permissions_flow_v1`: executable_advisory (contract 1.0.0, strict_ready=False, candidate_bound=False)
- `deployment.trusted_profile_v1`: executable_advisory (contract 1.0.0, strict_ready=False, candidate_bound=False)
- `infrastructure.kubernetes.controller_reachability_v1`: executable_advisory (contract 1.0.0, strict_ready=False, candidate_bound=False)
- `infrastructure.terraform.plan_recursive_v1`: executable_advisory (contract 1.0.0, strict_ready=False, candidate_bound=False)

## Open blockers

- verified_source_sha deferred to WP-17 release ledger
- externally_calibrated_strict not claimed
- authorization.express.ast_v1: not strict_ready
- authorization.fastapi.ast_v1: not strict_ready
- ci_secrets.actions.permissions_flow_v1: not strict_ready
- deployment.trusted_profile_v1: not strict_ready
- infrastructure.kubernetes.controller_reachability_v1: not strict_ready
- infrastructure.terraform.plan_recursive_v1: not strict_ready
