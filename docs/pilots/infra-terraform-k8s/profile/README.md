# In-repo infrastructure pilot profile

Designated Terraform / Kubernetes-oriented adopter profile used when no live
`ovk-consumer-*-infra` remote exists.

| Field | Value |
|---|---|
| Kind | Maintained in-repo profile (not true external OSS) |
| Registry id | `in-repo/ovk-pilot-infra-terraform-k8s` |
| Manifest | [`examples/pilot_repos/infra_terraform_k8s.json`](../../../examples/pilot_repos/infra_terraform_k8s.json) |
| Workflow scaffold | [`ovk-pilot.workflow.yml`](ovk-pilot.workflow.yml) |
| Report | [`../REPORT.md`](../REPORT.md) |

## Intent

Provide a reproducible advisory path for infrastructure-heavy stacks:

1. Run infrastructure exposure + CI secrets manifests in advisory mode.
2. Exercise known-bad public resource diffs (`examples/multi_surface/infra_public_s3.diff`, repair-loop failing diff).
3. Publish metrics under `docs/pilots/infra-terraform-k8s/` and ingest into the external pilots registry.

## Local reproduction

```bash
ovk verify --manifest examples/pilot_repos/infra_terraform_k8s.json --advisory
ovk check --changed-files examples/repair_loops/infrastructure/passing.diff --advisory
ovk check --changed-files examples/repair_loops/infrastructure/failing.diff --advisory
ovk check --changed-files examples/multi_surface/infra_public_s3.diff --advisory
```

When a live infra consumer remote is created, replace the registry id, keep the
`maintained_consumer` vs `true_external_oss` label explicit, and re-run the
[EXTERNAL_PILOT_PLAYBOOK.md](../../../EXTERNAL_PILOT_PLAYBOOK.md) window before strict mode.
