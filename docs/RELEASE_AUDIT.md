# Release audit responses

Answers to the external engineering review of OVK v1.2.0 readiness.

## Metric provenance

| Claim | Source |
|---|---|
| **376 passed, 12 skipped** | Local `pytest` after audit fixes (includes `tests/test_parallel_execution_order.py`). Re-run: `pytest -q` |
| **130/130 FormalPR-Bench** | `ovk bench --expanded` on the same commit; artifacts in `docs/benchmarks/latest-leaderboard-summary.json` |
| **12 required preflight checks** | `ovk release-preflight` on the same commit |
| **CI workflow green** | Verify on GitHub: [Actions → CI workflow](https://github.com/fraware/open-verification-kernel/actions/workflows/ci.yml) for the commit under test |

Badge-only commits tagged `[skip ci]` intentionally skip workflows. They do not invalidate prior green runs on the preceding feature commit. Always trace health claims to the last **non–skip-ci** commit that ran `ci.yml`.

## Review questions

### 1. Which commit produced the 374 passed claim?

Commit `ff894c4` — `Release v1.2.0 with adoption tooling and documentation updates.`

### 2. Was the latest `[skip ci]` badge commit intentional?

Yes. The badge updater commits leaderboard JSON only and uses `[skip ci]` to avoid redundant full CI. Release metrics should reference the preceding feature commit or a fresh CI run after fixes land.

### 3. Is `Development Status :: 5 - Production/Stable` intentional?

The package classifier is **Beta** (`Development Status :: 4`) until external pilot metrics are published. v1.2.0 is a **release candidate**: feature-complete for the five check types, pending proven CI runs on HEAD and external adoption evidence.

### 4. What do required native backend checks mean?

Required-in-CI backends (OPA, Z3, CBMC, Cedar) must:

- install the native binary in CI when the job is labeled “native execution”;
- run the native path when the binary is present;
- fall back to the built-in evaluator when it is not;
- never claim `used_native_binary=True` when only the built-in path ran.

Binary presence probes plus deterministic oracle comparison are acceptable **validation** steps; consumer evidence must remain honest about which path executed.

### 5. Must `ovk check` bundle IDs be reproducible across parallel runs?

Yes. Parallel obligation execution must preserve submission order. Fixed in `ovk.core.adapter_runtime.execute_obligations` and `ovk.core.multi_lane.run_verification_manifest`. Regression tests: `tests/test_parallel_execution_order.py`.

### 6. Is strict mode safe today?

Strict mode is **safe to enable on a repository after advisory calibration** on that repo's diffs (target: under 5% false positives). It is not a blanket “enable everywhere immediately” switch. See [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md).

## Remaining gaps (acknowledged)

- Externally validated GitHub Action usage metrics from community repos
- Full CBMC harness execution (contract check today)
- Complete CLI/script parity audit
- Deeper schema coverage for every emitted artifact type

## Fixes applied from this audit

1. Deterministic ordering in `execute_obligations` and `run_verification_manifest`
2. Regression tests for parallel execution order
3. `preflight.report.schema.json` aligned with `messages` and `optional_checks`
4. GitHub Action shell steps pass user inputs through environment variables
5. Evidence-quality exit codes combined correctly on verify/check paths
