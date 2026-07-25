# Reproducible baseline (OVK-01)

This document describes how to record and validate a multi-OS, multi-Python
reproducible baseline for Open Verification Kernel.

## What is recorded

Each baseline JSON under `docs/baselines/` follows
`schemas/repro.baseline.schema.json` (`ovk.repro_baseline.v1`) and includes:

- Python version, OS, and platform string
- Optional checker availability from `ovk doctor`
- Skipped pytest names (when available from output)
- Artifact paths with SHA-256 digests
- Network access flag (`true`/`false`, overridable via `OVK_NETWORK_ACCESS`)
- Wall-clock `started_at` / `completed_at` / `elapsed_seconds`
- Per-command argv, exit code, and elapsed time

## Commands

The harness runs (or orchestrates) exactly:

```bash
pip install -e '.[dev]'
pytest
ovk doctor
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk release-preflight
python examples/repair_loops/ci_secrets/demo_repair_loop.py
```

If `.verification/` is missing, the harness runs `ovk init` once so `ovk doctor`
can succeed. That setup step is noted in the baseline `notes` field.

## Local recording

```bash
python scripts/sync_package_data.py
pip install -e '.[dev]'
python scripts/record_repro_baseline.py --skip-install
```

Output defaults to `docs/baselines/repro-<os>-py<major.minor>.json`.

Validate an existing file:

```bash
python scripts/record_repro_baseline.py --validate-only docs/baselines/repro-linux-py3.12.json
```

## CI

Workflow: [`.github/workflows/repro-baseline.yml`](../.github/workflows/repro-baseline.yml)

Matrix: `ubuntu-latest`, `macos-latest`, `windows-latest` × Python `3.10` / `3.12`.

Each cell uploads the baseline JSON. The job fails when the schema is incomplete
even if individual commands exit non-zero (command outcomes are still recorded).

`docs/baselines/` may be empty in a fresh clone: multi-OS records are CI artifacts.
See [baselines/README.md](baselines/README.md). In-repo RC DoD does not require committed
baseline JSON; live matrix evidence is a maintainer publication gate.

## Related

- Adoption dashboard: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)
- Capability registry: [BACKENDS.md](BACKENDS.md)
