# Pilot report — JS/TS / Express + GitHub Actions

**Status:** Advisory metrics published (complete playbook workflow reproduction on fixtures).  
**Consumer kind:** Maintained consumer (not true independent external OSS).  
**Repository:** [fraware/ovk-consumer-express-actions](https://github.com/fraware/ovk-consumer-express-actions)  
**Measurement basis:** Fixture and dogfood runs (2026-07-11 – 2026-07-25).  
**OVK pin:** `1.2.1` / Action `@v1.2.1`

Machine-readable companions: [`pilot-report.json`](pilot-report.json) (`ovk.pilot_report.v1`), [`external_pilot_report.json`](external_pilot_report.json).


**Historical-data interpretation correction (2026-10-15):** The original companion JSON files preserve fixture counts and earlier self-reported error fields for historical inspection. Those fields have no independently adjudicated ground truth; the normalized external-pilot registry and adoption summary now record the rates as **null/unknown**. This clarification is not a new measurement.

## Repository profile

| Field | Value |
|---|---|
| Stack | TypeScript Express service with GitHub Actions workflows |
| Role | Maintained consumer fixture validation (not independent adoption) |
| Advisory workflow | `.github/workflows/ovk-advisory-pr.yml` |
| Pilot ledger | Consumer `pilot/ledger.json` (automated_scenario rows only) |
| Production gate | `production_gate_met: false` |

## Checks selected

| Check type | Why |
|---|---|
| `ci_secrets` | Primary playbook starter for workflow-heavy repos |
| `self_protection` | Agent CI-gate integrity for Actions-centric consumers |

Manifests exercised: `examples/pilot_repos/express_actions_consumer.json`, `examples/pilot_repos/external_oss_ci_secrets.json`.

## Workflow reproduction (complete)

Documented playbook path reproduced locally against the consumer clone:

1. Advisory `ovk check` on `fixtures/diffs/advisory_passing.diff` → `allow`
2. Advisory `ovk check` on `fixtures/diffs/advisory_failing.diff` → `block`
3. Advisory pilot manifest verify for CI secrets + self-protection safe fixtures → `allow`
4. Metrics packaged into `pilot-report.json` + `external_pilot_report.json` for registry ingest

## False positives

| Metric | Measured |
|---|---|
| Independently adjudicated false positives | **Unknown** — fixture decisions lack independent reviewer ground truth |
| Independently adjudicated false-positive rate | **Unknown** — 2 fixtures do not estimate an external error rate |

## False negatives

| Metric | Measured |
|---|---|
| Independently adjudicated false negatives | **Unknown** — only specified known-bad fixtures were exercised |

Unsafe secrets-on-PR fixture blocked as expected.

## Unknowns

| Source | Count / note |
|---|---|
| Fixture check cases in this report | **0** unknowns |
| Broader consumer scenario matrix | Timeout/unavailable backend scenarios remain honest non-pass outcomes in the ledger |

Live production unknown rate: **unmeasured**.

## Human review burden

| Signal | Observation |
|---|---|
| Fixture advisory runs | Low — decisions matched fixtures |
| Consumer ledger | Automated scenarios only |
| Live PR review load | Not measured |

## Configuration changes

- Historical workflow used `@v1.2.1`; for any newly consented advisory experiment, review and pin the full source commit `a27d5720f4350c00bca34f71d991c31f5a2f38c7` and its transitive dependencies. The historical tag is unsigned/unprotected.
- Advisory mode + `default_on_unknown: require_human_review`.
- `.verification/ci_secrets_pilot.json` in the consumer; in-repo mirror `examples/pilot_repos/express_actions_consumer.json`.
- `post-comment` / `emit-check` exercised on the advisory PR workflow path.

## Strict-mode recommendation

**Remain advisory (`remain_advisory`).** These controlled fixture outcomes do not establish an externally adjudicated error rate. Without a live, independently reviewed advisory cohort and qualified source/profile and release controls, strict branch protection is unauthorized.

Median `ovk check` latency on fixture diffs: ~82 ms.
