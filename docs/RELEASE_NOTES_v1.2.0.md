# OVK v1.2.0

Improves reliability for teams adopting OVK in GitHub Actions: all five check types are validated the same way, the Action exposes clearer outputs, and example workflows show how to roll out advisory → strict enforcement.

## Highlights

- **Consistent quality checks** — all five check types (self-protection, authorization, infrastructure, CI secrets, deployment) are validated in release checks, local smoke tests, CI, and dedicated tests per check type.
- **Clearer GitHub Action** — outputs `recommendation`, `exit_code`, and `check_emitted`; in strict mode, a failed check-run publish fails the job; five-check manifest runs also validate evidence quality in strict mode.
- **External validation fixes** — weekly CI scenarios now pass the correct Action inputs and assert expected outcomes after each run.
- **Example workflows** — `examples/github_workflows/` includes advisory-only, advisory with comments/checks, strict enforcement, and branch-protection wiring.
- **Branch protection guide** — required check name **Open Verification Kernel**, permissions template, when to supply explicit required-check metadata.
- **Policy config** — `default_on_unknown` in `.verification/config.yml` is honored when running `ovk check`.
- **Release status page** — [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) and [adoption-summary.json](benchmarks/adoption-summary.json).

## Quick start

```bash
pip install -e '.[dev]'   # or pip install open-verification-kernel==1.2.0 after PyPI publish
ovk doctor
ovk release-preflight
ovk bench --expanded
```

## GitHub Action

```yaml
env:
  OVK_PACKAGE_VERSION: "1.2.0"
jobs:
  ovk:
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@v1.2.0
        id: ovk
        with:
          mode: advisory
          use-check: "true"
          emit-check: "true"
```

For in-repo development, omit `OVK_PACKAGE_VERSION` and use `uses: ./`.

## Upgrade from v1.1.0

- Pin Action and PyPI to `1.2.0` / `@v1.2.0`.
- Add `checks: write` when `emit-check: "true"`.
- Read [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) before switching to strict mode.
- Copy a workflow from `examples/github_workflows/`.

## Documentation

- [Integration guide](INTEGRATION.md)
- [External rollout playbook](EXTERNAL_PILOT_PLAYBOOK.md)
- [Maintainer release guide](RELEASE.md)
