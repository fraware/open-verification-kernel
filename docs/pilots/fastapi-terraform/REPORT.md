# Pilot report — Python / FastAPI + Terraform

**Status:** Advisory metrics published (complete playbook workflow reproduction on fixtures).  
**Consumer kind:** Maintained consumer (not true independent external OSS).  
**Repository:** [fraware/ovk-consumer-fastapi-terraform](https://github.com/fraware/ovk-consumer-fastapi-terraform)  
**Measurement basis:** Fixture and dogfood runs (2026-07-11 – 2026-07-25).  
**OVK pin:** `1.2.1` / Action `@v1.2.1`

Machine-readable companions: [`pilot-report.json`](pilot-report.json) (`ovk.pilot_report.v1`), [`external_pilot_report.json`](external_pilot_report.json).

## Repository profile

| Field | Value |
|---|---|
| Stack | FastAPI web app with Terraform infrastructure |
| Role | Independent maintained consumer gate (program section 23) |
| Advisory workflow | `.github/workflows/ovk-advisory-pr.yml` |
| Pilot ledger | Consumer `pilot/ledger.json` (automated_scenario rows only) |
| Production gate | `production_gate_met: false` (no 30 human adjudications yet) |

## Checks selected

| Check type | Why |
|---|---|
| `ci_secrets` | Primary playbook starter for agent-authored workflow PRs |
| `infrastructure` | Aligns with Terraform surface in the consumer |

Manifests exercised: `examples/pilot_repos/fastapi_terraform_consumer.json`, `examples/pilot_repos/ci_secrets_only.json`.

## Workflow reproduction (complete)

Documented playbook path reproduced locally against the consumer clone:

1. Advisory `ovk check` on `fixtures/diffs/advisory_passing.diff` → `allow`
2. Advisory `ovk check` on `fixtures/diffs/advisory_failing.diff` → `block` (job remains non-blocking in advisory)
3. Advisory `ovk verify` / pilot manifest run for CI secrets + infrastructure safe fixtures → `allow`
4. Metrics packaged into `pilot-report.json` + `external_pilot_report.json` for registry ingest

## False positives

| Metric | Measured |
|---|---|
| False positives | **0** |
| False positive rate | **0.0** (0/2 fixture cases) |

Passing workflow fixture was allowed; no incorrect blocks on the known-good case.

## False negatives

| Metric | Measured |
|---|---|
| False negatives | **0** |

Known-bad secrets-on-`pull_request` fixture was blocked as expected (100% block rate on that unsafe fixture).

## Unknowns

| Source | Count / note |
|---|---|
| Fixture check cases in this report | **0** unknowns |
| Broader consumer scenario matrix | Native backend timeout path records `unknown` honestly (ledger `auto-native_backend_timeout`); not counted as FP/FN |

No live PR adjudications yet — unknown appropriateness for production traffic remains **unmeasured**.

## Human review burden

| Signal | Observation |
|---|---|
| Fixture advisory runs | Low — allow/block decisions matched fixtures without manual override |
| Consumer ledger | All rows `human_adjudication: automated_scenario` |
| Live PR review load | Not measured (no 14-day live adopter window in this publication) |
| Gate to reduce review | Accumulate human adjudications per [CONSUMER_VALIDATION_CHECKLIST.md](../../CONSUMER_VALIDATION_CHECKLIST.md) |

## Configuration changes

- Pin Action to `fraware/open-verification-kernel@v1.2.1` (immutable tag / audited SHA only).
- Advisory mode via `.verification/config.yml` (`mode: advisory`, `default_on_unknown: require_human_review`).
- Pilot manifest under `.verification/ci_secrets_pilot.json` (consumer) mirrored by in-repo `examples/pilot_repos/fastapi_terraform_consumer.json`.
- Artifact upload of evidence / comment outputs for ingest.

## Strict-mode recommendation

**Remain advisory (`remain_advisory`).** Fixture FP rate is under 5%, but this publication is maintained-consumer dogfood without human-adjudicated live PRs. Do not enable strict required checks on protected branches from this evidence alone.

Median `ovk check` latency on fixture diffs: ~96 ms.
