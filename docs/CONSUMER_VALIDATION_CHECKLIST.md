# Consumer Validation Checklist

Scaffolding and live pointers for independent consumer repositories validating OVK.
Completing this checklist for one repo does **not** satisfy the multi-repo production
exit criterion (30 human-adjudicated PRs per independent consumer).

## Live independent consumers (v1.2.1)

| Repository | Stack | Ledger |
|---|---|---|
| [fraware/ovk-consumer-fastapi-terraform](https://github.com/fraware/ovk-consumer-fastapi-terraform) | FastAPI + Terraform | [`pilot/ledger.json`](https://github.com/fraware/ovk-consumer-fastapi-terraform/blob/main/pilot/ledger.json) |
| [fraware/ovk-consumer-express-actions](https://github.com/fraware/ovk-consumer-express-actions) | Express + GitHub Actions | [`pilot/ledger.json`](https://github.com/fraware/ovk-consumer-express-actions/blob/main/pilot/ledger.json) |

Both pin `fraware/open-verification-kernel@v1.2.1` (never `uses: ./`). CI fails on pin drift via `scripts/assert_ovk_pin.py`.

## Immutable pin requirements

Consumers must pin an **immutable** OVK commit SHA or release tag.

```yaml
env:
  OVK_PACKAGE_VERSION: "1.2.1"
steps:
  - uses: fraware/open-verification-kernel@v1.2.1
```

Forbidden:

- `uses: ./`
- `uses: fraware/open-verification-kernel@main`
- floating refs without a tag or full commit SHA

## Checklist (per consumer)

- [x] Workflow copies from `docs/templates/consumer_validation.workflow.yml` (or equivalent) with an immutable pin.
- [x] Automated scenario matrix covers program section 23.1 intents (see consumer README).
- [x] Adjudication rows recorded in a pilot ledger conforming to `schemas/pilot.ledger.schema.json`.
- [ ] Human adjudications reach 30 PRs (entries must not remain `automated_scenario` / `pending` only).
- [ ] True cross-fork PR exercised and ledger-adjudicated (see consumer `docs/FORK_PR.md`).
- [ ] Prefer PyPI `open-verification-kernel==1.2.1` once published; until then Release wheel + cosign verify-blob.

## What this does not claim

- Declaring two independent consumer repos with 30 adjudicated PRs complete
- Vision completion or Production-stable package status
- That FormalPR-Holdout results generalize to these consumers (holdout is a separate program)
