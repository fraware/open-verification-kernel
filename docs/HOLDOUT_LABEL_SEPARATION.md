# Label-Separated Holdout Evaluation (Sprint 8)

Checklist for R2 Sprint 8. Builds on Phase A FormalPR-Holdout isolation
(`scripts/run_formalpr_holdout.py`, `.github/workflows/holdout-eval.yml`).

## Required flow

1. **Predict** using the exact RC artifact (wheel / Action pin) **without** access to protected labels.
2. **Digest** the predictions file (`scripts/digest_holdout_predictions.py`) — refuses embedded labels / ground-truth fields; emits SHA-256 record.
3. **Evaluate separately** with protected labels (token only on download step; evaluator env token-free).
4. **Publish aggregates only** (`formalpr_holdout.aggregate_metrics.v1`).

## In-repo artifacts

| Item | Path / note |
|---|---|
| Runner | `scripts/run_formalpr_holdout.py` (requires `--asset-sha256`; validates predictions are label-free) |
| Predictions digest | `scripts/digest_holdout_predictions.py` |
| Workflow | `.github/workflows/holdout-eval.yml` (download vs eval token split) |
| Predictions placeholder | `.verification/holdout-predictions.json` (never commit labels) |
| Governance | [FORMALPR_HOLDOUT_GOVERNANCE.md](FORMALPR_HOLDOUT_GOVERNANCE.md) |

## Checklist

- [ ] RC predictions generated in an environment without `corpus/labels`
- [ ] Predictions digested (`digest_holdout_predictions.py`) and retained with workflow ID
- [ ] `HOLDOUT_ASSET_SHA256` (or workflow input) set for immutable asset verify
- [ ] Eval job runs with tokens unset; aggregates schema-validated
- [ ] Published metrics cite `ovk_commit_sha` / `benchmark_source_sha` and do not embed case ids
- [ ] Do not set `verified_source_sha` on holdout aggregates unless the full required-workflow set was observed

## Blocked outside this repo

Protected label store and annotator workflow live in `fraware/FormalPR-Holdout` (private).
This repository cannot complete live holdout scoring without that access.
