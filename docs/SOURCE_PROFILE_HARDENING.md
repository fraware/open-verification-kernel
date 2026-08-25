# Source Profile Hardening (Sprint 6)

Hardening beyond scaffolding. Authoritative program:
[ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md).

## Goals

Replace regex-only / heuristic extraction with explicit **source profiles** that
authorize deeper analysis only when trusted materials are present:

| Lane | Hardening target |
|---|---|
| Authorization | AST / module-graph profiles (FastAPI, Express) |
| Infrastructure | Recursive Terraform plan expansion; controller-aware Kubernetes reachability |
| CI secrets | Deeper Actions permissions and secret-flow modeling |
| Deployment | Strictness only on explicit trusted profiles |

## Status in this tree

| Profile | Implementation |
|---|---|
| `authorization.fastapi.ast_v1` | `FastApiAstAuthorizationCompiler` (Python AST; preferred over regex) |
| `authorization.express.ast_v1` | Express AST + module-graph compilers (`express_ast`, `module_graph`) with support contract |
| `infrastructure.terraform.plan_recursive_v1` | Recursive `child_modules` walk in `compile_terraform_plan` |
| `infrastructure.kubernetes.controller_reachability_v1` | Service selector edges to Deployment/StatefulSet/DaemonSet |
| `ci_secrets.actions.permissions_flow_v1` | Permissions + secret extraction via `compile_workflow_trust` |
| `deployment.trusted_profile_v1` | Strictness gated on explicit `trusted_profile.v1.json` material |

Evidence collection for template conformance runs these provers from
`ovk/core/source_profile_evidence.py`. Profile IDs and compiler bindings live in
`ovk/core/source_profiles.py`. Machine maturity: regenerate [STATUS.md](STATUS.md)
via `python scripts/build_project_status.py`.

## Remaining gaps (honest)

- Actions composite/reusable recursion beyond current trust-flow expansion.
- Deployment strictness still requires explicit trusted profile material; absence forces review.
- Local `source_profile_strict_eligible` does **not** imply production-ready general enforcement.
- `externally_calibrated_strict` is never granted by local generation alone.

## Gate

`source_profile_strict_eligible` requires:

1. profile ID recorded on the obligation / evidence;
2. materials marked trusted with matching profile provenance;
3. coverage status `complete` for the profile's extracted elements;
4. enforcement test covering the profile path.
