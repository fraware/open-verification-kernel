# FormalPR-Bench

FormalPR-Bench is OVK's regression suite. It scores whether checks return the right recommendation, pick the right backend, produce useful repair hints, and handle realistic PR diffs.

## Public artifacts

- `docs/benchmarks/leaderboard-badge.json` — README badge data
- `docs/benchmarks/latest-leaderboard-summary.json` — summary for dashboards
- `docs/benchmarks/adoption-summary.json` — adoption metrics alongside bench scores
- `.verification/formal-pr-bench-leaderboard.json` — full results from `ovk bench` (CI artifact)

Regenerate after a bench run:

```bash
ovk bench --expanded --leaderboard .verification/formal-pr-bench-leaderboard.json
python scripts/render_bench_badge.py --leaderboard .verification/formal-pr-bench-leaderboard.json
```

## What is measured

| Dimension | Meaning |
|---|---|
| Pass rate | Fraction of cases where OVK matched expected outcomes |
| Merge decision accuracy | `allow`, `block`, or `require_human_review` matches expectation |
| Status accuracy | Backend `pass`, `fail`, or `unknown` matches expectation |
| Counterexample usefulness | Repair hints and failure modes match expectation |
| Backend selection | Right checker chosen for the changed files |
| Evidence honesty | Forged or inconsistent bundles are rejected |
| Check detection | Expected checks are identified from a diff |
| Realistic PR diff score | End-to-end `ovk check` on sanitized agent-style diffs |

## Test categories

| Category | What it exercises |
|----------|-------------------|
| `lane` | Each check type with fixed input fixtures |
| `routing` | Picking backends from changed file paths |
| `adversarial` | Tampered evidence is caught |
| `repair_loop` | Block → useful repair hint → allow after fix |
| `intent_recall` | Check planner finds expected checks from example diffs |
| `multi_backend` | PRs that touch multiple check types |
| `real_diff` | Full `ovk check` on sanitized PR diffs |

## Realistic PR diff set

- 16 diffs in `benchmarks/real_diffs/` (secrets, auth, infra, deployment, multi-surface, partial hunks).
- Manifest: `benchmarks/real_diffs/manifest.json`.
- Integration tests: `tests/test_real_diffs.py` (≥95% check detection rate required).

```bash
pytest tests/test_real_diffs.py -v
```

## Category pass rates

`latest-leaderboard-summary.json` includes per-category pass rates so dashboards can track trends without parsing the full leaderboard.

Category IDs such as `lane` and `intent_recall` are historical names in the benchmark schema. In docs they mean **check-type fixtures** and **check detection from diffs**, respectively.

## Adoption metrics JSON

`docs/benchmarks/adoption-summary.json` uses schema field names such as `pilot_dogfood` and `intent_recall` for machine-readable compatibility. They refer to the **in-repo weekly pilot workflow** and **check detection rate**, not separate product features.
