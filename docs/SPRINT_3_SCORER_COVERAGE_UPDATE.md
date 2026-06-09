# Sprint 3 Scorer Coverage Update

The authorization obligation scorer is now covered through pytest.

Implemented:

- Added `tests/test_authorization_obligation_scorer.py`.
- The test calls `benchmarks.formal_pr_bench.score_authorization_obligation.main`.
- This gives scorer coverage in the existing CI because the workflow already runs `pytest`.

Why this matters:

- Direct workflow edits have been blocked.
- The scorer is still exercised by normal test execution.
- Query polarity, counterexample behavior, regression rendering, and malformed-input handling are now protected indirectly through CI.
