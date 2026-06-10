# OVK Evidence Lanes

The five MVP evidence lanes and their input contracts.

## Lane overview

| Lane | Intent ID | CLI | Input schema |
|---|---|---|---|
| Self-protection | `agent-cannot-disable-own-ci-gate` | `ovk ci` | metadata + changed files |
| Authorization | `no-admin-route-bypass` | `ovk auth-obligation` | `authorization.input` |
| Infrastructure | `no-public-sensitive-resource` | `ovk infra-exposure` | `infrastructure.input` |
| CI secrets | `no-secrets-in-untrusted-context` | `ovk ci-secrets` | `ci_secrets.input` |
| Deployment state | `no-skipped-approval-state` | `ovk deployment-state` | `deployment_state.input` |

Multi-lane: `ovk verify --manifest <manifest.json>`

## Self-protection

Checks that AI-authored changes do not weaken verification controls governing merge.

```bash
ovk ci \
  --metadata examples/no_agent_self_approval/metadata_gate_preserved.json \
  --changed-files examples/no_agent_self_approval/changed_files_workflow.txt \
  --advisory
```

| Condition | Recommendation |
|---|---|
| Required check removed | `block` |
| Missing required-check metadata | `require_human_review` |
| Controls preserved | `allow` |

Backend: deterministic evaluator (default), optional OPA via `--backend-strategy`.

## Authorization

Checks that non-admin principals cannot reach admin-only routes.

```bash
ovk auth-obligation examples/auth_regression/input_admin_bypass.json --advisory
```

Input schema: `schemas/authorization.input.schema.json`

Required field: non-empty `routes` list. Each route has `path`, `admin_only_before`, `admin_only_after`, and `reachable_after`.

| Solver result | Recommendation |
|---|---|
| Violation found | `block` |
| No violation | `allow` |
| Solver unavailable | `require_human_review` |

Optional Z3 backend: `pip install -e '.[solvers]'`

## Infrastructure exposure

Checks that sensitive resources are not publicly exposed.

```bash
ovk infra-exposure examples/infrastructure_exposure/input_public_sensitive_resource.json --advisory
```

Input schema: `schemas/infrastructure.input.schema.json`

### Input formats

`ovk infra-exposure` and `scripts/run_infra_exposure.py` accept:

| Format | Flag |
|---|---|
| Native OVK infra | `--input-format infra` (default) |
| Terraform-plan subset | `--input-format terraform` |
| Kubernetes Service subset | `--input-format kubernetes` |
| Graph-style | `--input-format graph` |

Normalizer: `ovk.adapters.infra.normalize`

### Policy

Optional policy file: `schemas/infrastructure.policy.schema.json`

```json
{
  "blocked_public_sensitivities": ["confidential", "restricted"]
}
```

Pass via `--policy <path>`.

| Condition | Recommendation |
|---|---|
| Sensitive resource publicly exposed | `block` |
| Resource remains private | `allow` |
| Invalid abstraction | `require_human_review` |

## CI secrets

Checks that secrets are not referenced in untrusted workflow contexts.

```bash
ovk ci-secrets examples/ci_secrets/input_secrets_exposed.json --advisory
ovk extract-workflow .github/workflows/deploy.yml
```

Input schema: `schemas/ci_secrets.input.schema.json`

Workflow YAML extraction handles PyYAML 1.1 `on:` → `True` quirk. Unified diffs reconstruct workflow content via `ovk plan` / `ovk infer`.

| Condition | Recommendation |
|---|---|
| Secrets on untrusted trigger (`pull_request`, etc.) | `block` |
| `pull_request_target` with PR head checkout + secrets | `block` |
| Safe context | `allow` |

## Deployment approval state

Checks that deployment state machines do not skip required approval states.

```bash
ovk deployment-state examples/deployment_state/input_skipped_approval.json --advisory
```

Input schema: `schemas/deployment_state.input.schema.json`

Uses graph reachability over deployment states. Skipped required approval → `block`.

## Conservative rule

Invalid input must not produce `allow`. Unknown and error states require human review across all lanes.

Examples: `examples/` per lane. Benchmark: `benchmarks/formal_pr_bench/score_all_lanes.py`.
