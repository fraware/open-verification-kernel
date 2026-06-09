# Sprint 4 Benchmark Update

The infrastructure exposure path now has benchmark scoring.

Implemented:

- Added `benchmarks/formal_pr_bench/score_infra_exposure.py`.
- Added `tests/test_infra_exposure_scorer.py`.
- Public sensitive resource exposure is scored as `fail` and `block`.
- Private sensitive resource exposure is scored as `pass` and `allow`.

The scorer is protected through pytest, so it runs under the existing test workflow even before direct workflow edits are made.
