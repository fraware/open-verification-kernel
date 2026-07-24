# Attributable Publication Checklist (Sprint 10)

Gate for publishing **`v1.3.0-rc.1`** and later promoting to **`v1.3.0`**.
Authority: [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md) 18-condition gate.

## Terminology

| Field | Use |
|---|---|
| `benchmark_source_sha` | FormalPR-Bench / badge measurement identity |
| `verified_source_sha` | Complete observed required-workflow set only |

Never label a `[skip ci]` badge commit as verified. Never re-attribute `v1.2.1`
Sigstore / consumer evidence to typed-control-plane commits.

## Collect workflow evidence (when Actions are available)

```bash
python scripts/collect_workflow_evidence.py \
  --sha <SOURCE_SHA> \
  --output .verification/workflow-evidence-<SOURCE_SHA>.json
```

The collector records run IDs/URLs under `benchmark_source_sha` and leaves
`verified_source_sha` unset until maintainers confirm the full required set.

## Pre-tag checklist (`v1.3.0-rc.1`)

- [ ] P0 trust PRs 1–9 landed on the tag source
- [ ] Non-`[skip ci]` CI, native Tier 1, wheel smoke, Action dogfood, release preflight green
- [ ] Expanded FormalPR-Bench recorded with `benchmark_source_sha`
- [ ] Template conformance v2 matrix regenerated from semantic statuses
- [ ] Both consumers dispatched on immutable rc.1 pin (or audited commit); evidence downloaded and verified
- [ ] Label-separated holdout aggregates retained (predictions digest + eval workflow IDs)
- [ ] Release artifacts signed; workflow IDs and digests recorded in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)

## Promote to `v1.3.0`

Only after:

- [ ] All 18 completion-gate conditions hold
- [ ] P0 closure (PRs 1–9) on the exact tag source
- [ ] Consumer validation on the exact pin
- [ ] Attributable holdout aggregates (predictions digest + eval)
- [ ] Human pilot ledgers remain separate from automated fixtures
- [ ] No re-attribution of `v1.2.1` Sigstore evidence to typed-control-plane commits

## Blocked without external access

Live GitHub Actions run URLs, consumer repo pin PRs, and private holdout evaluation require
maintainer credentials outside this working tree.
