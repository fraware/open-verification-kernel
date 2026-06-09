# Sprint 3 Benchmark Validation Update

This note supplements `docs/SPRINT_3_BENCHMARK_UPDATE.md`.

## Completed in this increment

- Extended `benchmarks/formal_pr_bench/score_authorization_obligation.py`.
- The scorer now covers malformed authorization abstractions.
- Missing route metadata must produce `unknown` and `require_human_review`.
- Malformed witness metadata must produce `unknown` and `require_human_review`.
- The scorer still checks query polarity, counterexample presence, protected-case behavior, and regression artifact rendering.

## Command

```bash
python benchmarks/formal_pr_bench/score_authorization_obligation.py
```

## Remaining work

- Add this scorer to CI when workflow edits are permitted.
- Add more malformed-input cases.
- Add explicit unknown-solver benchmark cases.
