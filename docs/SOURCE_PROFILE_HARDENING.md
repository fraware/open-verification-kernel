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
| `authorization.express.ast_v1` | Express compiler still regex/module-import based; deeper module-graph pending |
| `infrastructure.terraform.plan_recursive_v1` | Recursive `child_modules` walk in `compile_terraform_plan` |
| `infrastructure.kubernetes.controller_reachability_v1` | Service selector edges to Deployment/StatefulSet/DaemonSet |
| `ci_secrets.actions.permissions_flow_v1` | Permissions + secret extraction via `compile_workflow_trust` |
| `deployment.trusted_profile_v1` | Strictness gated on explicit `trusted_profile.v1.json` material |

Evidence collection for template conformance v2 runs these provers from
`ovk/core/source_profile_evidence.py`. Profile IDs and compiler bindings live in
`ovk/core/source_profiles.py`.

## Remaining gaps (honest)

- Express AST / full module-graph resolution is not yet equivalent to FastAPI AST.
- Actions composite/reusable recursion beyond current trust-flow expansion.
- Deployment does **not** claim `source_profile_strict_eligible` until an explicit
  trusted profile material is present under `examples/deployment_state/`.
- `externally_calibrated_strict` is never granted by local generation alone.

## Gate

`source_profile_strict_eligible` requires:

1. profile ID recorded on the obligation / evidence;
2. materials marked trusted with matching profile provenance;
3. coverage status `complete` for the profile's extracted elements;
4. enforcement test covering the profile path.
