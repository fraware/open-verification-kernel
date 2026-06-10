# OVK v1.1.0

Depth-first release of the Open Verification Kernel: native proof ladder, real diff benchmarks, and external adoption tooling.

## Highlights

- **Tier-1 native CI** — OPA, Z3, and CBMC run as required jobs when installed; evidence honesty gates flag oracle-only claims
- **Real diff corpus** — 16 sanitized PR diffs in `benchmarks/real_diffs/` for lane recall and compiler regression
- **FormalPR-Bench depth** — `real_diff` category, repair-loop cases across ci_secrets, authorization, infra, and deployment lanes
- **PyPI-pinned Action** — `OVK_PACKAGE_VERSION=1.1.0` installs `open-verification-kernel==1.1.0`; local dev still uses `pip install .`
- **External pilot kit** — advisory→strict playbook, OSS manifest template, metrics template in case studies

## Quick start

```bash
pip install open-verification-kernel==1.1.0
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
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@v1.1.0
        with:
          mode: advisory
          use-check: "true"
```

For in-repo development, omit `OVK_PACKAGE_VERSION` and use `uses: ./`.

## Upgrade from v1.0.0

- Pin Action and PyPI to `1.1.0` / `@v1.1.0`.
- Set `OVK_PACKAGE_VERSION` at job or workflow level when consuming the published wheel.
- Review [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) before enabling strict mode on protected branches.

## Documentation

- [Integration guide](INTEGRATION.md)
- [External pilot playbook](EXTERNAL_PILOT_PLAYBOOK.md)
- [Release maintainer checklist](RELEASE.md)
- [Status](STATUS.md)
