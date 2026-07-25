# OVK External Pilot Reports (OVK-PR8 / OVK-09)

Published advisory pilot evidence for the adoption-surface program. These reports are
**maintained-consumer / in-repo profile** measurements, not claims of independent
external OSS production readiness.

| Pilot | Repository | Stack | Kind | Workflow reproduction | Report |
|---|---|---|---|---|---|
| Python | [fraware/ovk-consumer-fastapi-terraform](https://github.com/fraware/ovk-consumer-fastapi-terraform) | FastAPI + Terraform | Maintained consumer | Complete | [fastapi-terraform/REPORT.md](fastapi-terraform/REPORT.md) |
| JS/TS | [fraware/ovk-consumer-express-actions](https://github.com/fraware/ovk-consumer-express-actions) | Express + Actions | Maintained consumer | Complete | [express-actions/REPORT.md](express-actions/REPORT.md) |
| Infrastructure | `in-repo/ovk-pilot-infra-terraform-k8s` | Terraform / K8s fixtures | In-repo maintained profile (no live remote) | Advisory metrics published | [infra-terraform-k8s/REPORT.md](infra-terraform-k8s/REPORT.md) |

## Artifacts per pilot

| File | Schema / role |
|---|---|
| `pilot-report.json` | [`schemas/pilot.report.schema.json`](../../schemas/pilot.report.schema.json) (`ovk.pilot_report.v1`) |
| `external_pilot_report.json` | Playbook self-report; ingested into [`docs/benchmarks/external-pilots-registry.json`](../benchmarks/external-pilots-registry.json) |
| `REPORT.md` | Human-readable profile, metrics, and strict-mode recommendation |
| `check-case-results.json` | Fixture-level `ovk check` outcomes used for FP/FN/unknown counts |

## Measurement honesty

- Metrics are from **fixture and dogfood runs** (consumer scenario diffs + in-repo manifests).
- Rows are labeled **maintained consumer** or **in-repo maintained profile**, not true independent external OSS.
- Consumer ledgers keep `production_gate_met: false` until 30 human-adjudicated PRs exist ([CONSUMER_VALIDATION_CHECKLIST.md](../CONSUMER_VALIDATION_CHECKLIST.md)).
- Strict mode is **not** recommended from these pilots alone.

## Reproduce

```bash
# Manifest pilot program (includes consumer-aligned manifests under examples/pilot_repos/)
ovk pilot --output .verification/pilot-program-report.json

# Re-ingest published self-reports into the registry
python scripts/ingest_external_pilot_metrics.py \
  --repo fraware/ovk-consumer-fastapi-terraform \
  --report docs/pilots/fastapi-terraform/external_pilot_report.json
python scripts/ingest_external_pilot_metrics.py \
  --repo fraware/ovk-consumer-express-actions \
  --report docs/pilots/express-actions/external_pilot_report.json
python scripts/ingest_external_pilot_metrics.py \
  --repo in-repo/ovk-pilot-infra-terraform-k8s \
  --report docs/pilots/infra-terraform-k8s/external_pilot_report.json

python scripts/render_pilot_metrics.py --registry docs/benchmarks/external-pilots-registry.json
```

Playbook: [EXTERNAL_PILOT_PLAYBOOK.md](../EXTERNAL_PILOT_PLAYBOOK.md). Case-study index: [PILOT_CASE_STUDIES.md](../PILOT_CASE_STUDIES.md).
