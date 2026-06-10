# OVK Check Types

The five check types OVK ships today and their input contracts.

**Default path:** `ovk check --changed-files <diff>` infers and evaluates all affected checks from a unified diff. Focused CLI commands below remain for debugging and manifest-driven workflows.

## Overview

| Check type | Intent ID | Focused CLI | Via `ovk check` |
|---|---|---|---|
| Self-protection | `agent-cannot-disable-own-ci-gate` | `ovk ci` | `ovk check` |
| Authorization | `no-admin-route-bypass` | `ovk auth-obligation` | `ovk check` |
| Infrastructure | `no-public-sensitive-resource` | `ovk infra-exposure` | `ovk check` |
| CI secrets | `no-secrets-in-untrusted-context` | `ovk ci-secrets` | `ovk check` |
| Deployment state | `no-skipped-approval-state` | `ovk deployment-state` | `ovk check` |

Multi-check manifest: `ovk verify --manifest <manifest.json>`

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

`ovk infra-exposure` accepts:

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

Invalid input must not produce `allow`. Unknown and error states require human review for every check type.

Examples: `examples/` per check type. Benchmark scorer: `benchmarks/formal_pr_bench/score_all_lanes.py` (internal script name).

## Older wrapper scripts

Deprecated `scripts/run_*.py` runners mirror the focused CLI commands above (`ovk ci`, `ovk auth-obligation`, `ovk infra-exposure`, `ovk ci-secrets`, `ovk deployment-state`) with identical flags. Prefer `ovk` for new integrations; see [MIGRATION.md](MIGRATION.md).
