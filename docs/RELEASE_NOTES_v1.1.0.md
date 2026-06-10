# OVK v1.1.0

Adds realistic PR diff benchmarks, required native checker CI, and guides for rolling out on external repositories.

## Highlights

- **Required native checker CI** — OPA, Z3, CBMC, and Cedar run as blocking jobs when installed; evidence must not falsely claim native execution
- **Realistic PR diff set** — 16 sanitized agent-style diffs in `benchmarks/real_diffs/`
- **Benchmark expansion** — `real_diff` category and repair-loop cases for all five check types
- **PyPI-pinned Action** — `OVK_PACKAGE_VERSION=1.1.0` installs `open-verification-kernel==1.1.0`
- **External rollout kit** — advisory→strict playbook, manifest template, pilot metrics template

## Quick start

```bash
pip install -e '.[dev]'
ovk doctor
ovk check --changed-files benchmarks/real_diffs/multi_surface_combined.diff --advisory
ovk pilot
ovk bench --expanded
```

## GitHub Action

```yaml
env:
  OVK_PACKAGE_VERSION: "1.1.0"
jobs:
  ovk:
    steps:
      - uses: fraware/open-verification-kernel@v1.1.0
        with:
          mode: advisory
          use-check: "true"
```

## Upgrade from v1.0.0

- Pin Action and PyPI to `1.1.0` / `@v1.1.0`.
- Review [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) before strict mode.
- Run `ovk bench --expanded` for the new realistic diff category.
