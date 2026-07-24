# FormalPR-Holdout Governance

Status: **Active program** (synthetic seed). This document points at the real
FormalPR-Holdout repository. It does **not** claim holdout evaluation is
complete at production scale, and must not be cited as evidence that OVK has
left Beta or achieved solver-agnostic vision goals.

## Canonical repository

| Item | Value |
|---|---|
| Repository | https://github.com/fraware/FormalPR-Holdout (private) |
| Local sibling checkout | `../FormalPR-Holdout` (when cloned beside OVK) |
| Frozen seed release | `v0.1.0-synthetic` |
| Aggregate schema | `formalpr_holdout.aggregate_metrics.v1` |

Protected labels live only in private release assets (and gitignored local
`corpus/labels/` on annotator machines). They are **not** in this OVK tree.

## Requirements (enforced by the holdout program)

1. **Access control** — Maintainers with need-to-know only; no public mirrors of protected cases/labels.
2. **No label leakage** — Holdout labels, expected recommendations, and adjudication notes must not appear in public issues, PRs, docs, or ordinary OVK CI logs.
3. **Immutable pins** — Evaluations pin `holdout_release_tag` and an immutable OVK commit (`ovk_commit_sha` / `verified_source_sha`). Never claim a score from a mutable working tree alone.
4. **Metrics** — Per-lane precision, recall, false-positive rate, missed-detection rate, unknown rate, invalid-input rate, abstention appropriateness, coverage completeness, counterexample correctness, selected-backend execution correctness, median/tail runtime, and aggregate reviewer time. Do **not** collapse to one pass-rate.
5. **Separation** — Annotators vs implementers (see holdout `CODEOWNERS` and docs). Holdout cases must not be copied into FormalPR-Bench, `examples/`, or public fixtures.
6. **Disagreements** — Recorded in the holdout repo; only aggregate counts may be published.
7. **Change control** — Dual annotator review + changelog inside the holdout repo for case/label changes.

## How OVK CI consumes holdout results

- Optional workflow: `.github/workflows/holdout-eval.yml` (`workflow_dispatch`, gated by secrets).
- Downloads a **versioned** private release asset from `fraware/FormalPR-Holdout`.
- Runs the harness shipped inside that artifact.
- Publishes **aggregate metrics only**; fails closed if labels or case ids would be printed.
- Ordinary `CI` jobs do **not** checkout holdout labels.

Runner: `scripts/run_formalpr_holdout.py` (requires immutable `--asset-sha256`).

Label-separated prediction/eval flow (Sprint 8): [HOLDOUT_LABEL_SEPARATION.md](HOLDOUT_LABEL_SEPARATION.md).

## What this is not

- Not a claim of production generalization measurement
- Not authorization to mark vision complete or Beta → Production
- Not a substitute for FormalPR-Bench regression (public, in-repo)
