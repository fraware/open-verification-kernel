# Pilot report — Infrastructure (Terraform / Kubernetes profile)

**Status:** Advisory metrics published (scaffold; no live remote consumer).  
**Consumer kind:** In-repo maintained profile — **not** a true independent external OSS repository.  
**Repository id:** `in-repo/ovk-pilot-infra-terraform-k8s`  
**Profile:** [profile/README.md](profile/README.md)  
**Measurement basis:** In-repo infrastructure fixtures and repair-loop diffs (2026-07-11 – 2026-07-25).  
**OVK pin:** working-tree package version (`1.2.1`)

Machine-readable companions: [`pilot-report.json`](pilot-report.json) (`ovk.pilot_report.v1`), [`external_pilot_report.json`](external_pilot_report.json).

## Repository profile

| Field | Value |
|---|---|
| Stack | Terraform-heavy infrastructure exposure + CI secrets (K8s-oriented adopter profile) |
| Live remote | **None** — designated in-repo pilot profile until an infra consumer repo exists |
| Manifest | `examples/pilot_repos/infra_terraform_k8s.json` |
| Workflow scaffold | [profile/ovk-pilot.workflow.yml](profile/ovk-pilot.workflow.yml) |

This pilot satisfies OVK-PR8’s third-pilot requirement at the **advisory metrics publication** bar. It does **not** claim a complete remote playbook reproduction.

## Checks selected

| Check type | Why |
|---|---|
| `infrastructure` | Primary signal for public/sensitive resource exposure |
| `ci_secrets` | Shared starter check from the external pilot playbook |

## False positives

| Metric | Measured |
|---|---|
| False positives | **0** |
| False positive rate | **0.0** (0/3 fixture cases) |

Private / repaired infrastructure fixtures allowed when expected.

## False negatives

| Metric | Measured |
|---|---|
| False negatives | **0** |

Public-sensitive and failing repair-loop fixtures blocked as expected.

## Unknowns

| Source | Count / note |
|---|---|
| Fixture check cases in this report | **0** unknowns |
| Live infra adopter traffic | **N/A** — no remote consumer |

## Human review burden

| Signal | Observation |
|---|---|
| Fixture runs | Low for the curated infra diffs |
| Expected for a future live infra consumer | Higher until exposure-graph coverage and policy digests stabilize; keep advisory |

## Configuration changes (profile scaffold)

- Copy [profile/ovk-pilot.workflow.yml](profile/ovk-pilot.workflow.yml) to `.github/workflows/ovk-pilot.yml` in a future infra consumer.
- Install manifest from `examples/pilot_repos/infra_terraform_k8s.json` (or consumer-local copy under `.verification/`).
- Start advisory-only; ingest artifacts via `scripts/ingest_external_pilot_metrics.py`.

## Strict-mode recommendation

**Remain advisory (`remain_advisory`).** Publish-only scaffold with fixture metrics. Promote to strict only after a live infra consumer completes the playbook window with FP under 5% and human adjudication.

Median `ovk check` latency on fixture diffs: ~46 ms.
