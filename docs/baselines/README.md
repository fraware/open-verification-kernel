# Reproducible baselines (OVK-01)

Generated and CI-uploaded reproducible baseline records.

Schema: `schemas/repro.baseline.schema.json` (`ovk.repro_baseline.v1`).
Procedure: [REPRO_BASELINE.md](../REPRO_BASELINE.md).
Workflow: [`.github/workflows/repro-baseline.yml`](../../.github/workflows/repro-baseline.yml).

## Why this directory may be empty locally

Multi-OS artifacts (`ubuntu` / `macos` / `windows` × Python `3.10` / `3.12`) are produced by
the `repro-baseline` GitHub Actions matrix and uploaded as workflow artifacts. They are **not**
required to be committed for in-repo RC DoD. Local trees often contain only this README until
a maintainer downloads CI artifacts or records a sample.

## Local sample (optional, single OS)

When the environment is already installed (`pip install -e '.[dev]'`):

```bash
python scripts/record_repro_baseline.py --skip-install
```

Writes `docs/baselines/repro-<os>-py<major.minor>.json` (for example `repro-windows-py3.13.json`).
That command runs the full harness including `pytest`, so expect minutes, not seconds.

Validate without recording:

```bash
python scripts/record_repro_baseline.py --validate-only docs/baselines/repro-<os>-py<ver>.json
```

## CI fill path

1. Push a non-`[skip ci]` commit that includes `.github/workflows/repro-baseline.yml`.
2. Open the Actions run for `repro-baseline`.
3. Download each matrix cell artifact into this directory (or retain them as release evidence).
4. Optionally commit selected JSON records once maintainers want them in-tree.

Do not invent multi-OS hashes by hand.
