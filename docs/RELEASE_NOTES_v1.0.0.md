# OVK v1.0.0

First stable release of the Open Verification Kernel with all five check types and ten backends.

## Highlights

- **`ovk check`** — diff-aware PR verification across all check types (default adoption path)
- **10 backends** — OPA, Z3, Cedar, TLA+, Kani, Dafny, Verus, Lean, CBMC, Alloy with deterministic fallbacks
- **Verification pipeline** — reads diffs, ranks risk, routes to backends, and compiles proof obligations
- **Agent loop** — MCP SDK transport, repair hints, counterexample-to-test, repo memory
- **FormalPR-Bench v1** — 100-case expanded set plus routing, adversarial, repair-loop, and check-detection categories
- **50+ intent templates** — schema-validated property library
- **Pilot program** — `ovk pilot` with five adoption manifests
- **PyPI package** — `pip install open-verification-kernel` (schemas, templates, and examples bundled in the wheel)

## Quick start

```bash
pip install open-verification-kernel
ovk doctor
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk pilot
ovk bench --expanded
```

## GitHub Action

```yaml
- uses: fraware/open-verification-kernel@v1.0.0
  with:
    mode: advisory
    use-check: "true"
```

## Documentation

- [Integration guide](INTEGRATION.md)
- [Migration from pre-1.0 builds](MIGRATION.md)
- [Release maintainer checklist](RELEASE.md)
