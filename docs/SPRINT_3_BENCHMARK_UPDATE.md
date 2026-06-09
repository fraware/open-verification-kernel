# Sprint 3 Benchmark Update

This note supplements `docs/SPRINT_3_STATUS.md`.

## Completed in this increment

- Added `benchmarks/formal_pr_bench/score_authorization_obligation.py`.
- The scorer checks that authorization obligations preserve query polarity.
- It checks that counterexamples are detected for the failing fixture.
- It checks that no counterexample is emitted for the protected fixture.
- It checks that regression artifact rendering is present when expected.

## Command

```bash
python benchmarks/formal_pr_bench/score_authorization_obligation.py
```

## Current CI status

The scorer is committed but not yet wired into `.github/workflows/ci.yml`. The workflow update was blocked by connector safety controls. Engineers can add the command manually to CI or run it locally until the workflow can be updated safely.

## Remaining work

- Add this scorer to CI.
- Add more adversarial authorization cases.
- Add cases for unknown solver outcomes.
- Add cases for malformed route abstractions.
