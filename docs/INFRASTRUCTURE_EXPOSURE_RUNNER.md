# Infrastructure Exposure Runner

The infrastructure exposure runner is the Sprint 4 demo path for public-exposure checks on sensitive infrastructure resources.

## Command

```bash
python scripts/run_infra_exposure.py \
  examples/infrastructure_exposure/input_public_sensitive_resource.json \
  --repo example/repo \
  --head-sha demo-head \
  --evidence-output ovk-infra-evidence.json \
  --markdown-output ovk-infra-comment.md \
  --attestation-output ovk-infra-attestation.json \
  --advisory
```

## Output files

The runner writes:

- `ovk-infra-evidence.json`
- `ovk-infra-comment.md`
- `ovk-infra-attestation.json`

## Result semantics

| Condition | OVK recommendation |
|---|---|
| confidential or restricted resource is publicly exposed | `block` |
| sensitive resource remains private | `allow` |
| infrastructure abstraction is invalid | `require_human_review` |

## Current limitation

The runner consumes a supplied infrastructure abstraction. It does not yet parse Terraform, Kubernetes, IAM, or cloud-provider configuration files directly.
