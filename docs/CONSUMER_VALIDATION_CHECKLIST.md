# Consumer Validation Checklist

Scaffolding and live pointers for independent consumer repositories validating OVK.
Completing this checklist for one repo does **not** satisfy the multi-repo production
exit criterion (30 human-adjudicated PRs per independent consumer).

## Live independent consumers

| Repository | Stack | Current pin | Target pin (Sprint 9) |
|---|---|---|---|
| [fraware/ovk-consumer-fastapi-terraform](https://github.com/fraware/ovk-consumer-fastapi-terraform) | FastAPI + Terraform | `v1.2.1` | immutable `v1.3.0-rc.1` (or audited commit) |
| [fraware/ovk-consumer-express-actions](https://github.com/fraware/ovk-consumer-express-actions) | Express + GitHub Actions | `v1.2.1` | immutable `v1.3.0-rc.1` (or audited commit) |

`v1.2.1` validates the **pre-control-plane** signed release only. Typed control-plane
commits must not inherit that consumer evidence. Both consumers use
`scripts/assert_ovk_pin.py` to fail on pin drift.

## Immutable pin requirements

Consumers must pin an **immutable** OVK commit SHA or release tag.

```yaml
env:
  OVK_PACKAGE_VERSION: "1.3.0rc1"   # after rc.1 cut; until then keep 1.2.1
  OVK_ACTION_REF: "v1.3.0-rc.1"
steps:
  - uses: fraware/open-verification-kernel@v1.3.0-rc.1
```

In-repo template: [templates/consumer_validation.workflow.yml](templates/consumer_validation.workflow.yml).

Forbidden:

- `uses: ./`
- `uses: fraware/open-verification-kernel@main`
- floating refs without a tag or full commit SHA

## Maintainer steps after `v1.3.0-rc.1` exists (do not push from this workspace alone)

For each consumer repository:

1. Open a pin PR that bumps Action `uses:` and `OVK_PACKAGE_VERSION` to the immutable rc.1 tag (or full SHA).
2. Merge the pin PR (or push to a validation branch) so workflows can see the new pin.
3. Dispatch validation:
   ```bash
   gh workflow run "OVK Consumer Validation" --repo fraware/ovk-consumer-fastapi-terraform
   gh workflow run "OVK Consumer Validation" --repo fraware/ovk-consumer-express-actions
   ```
   (Use the exact workflow name as defined in each consumer.)
4. Await conclusions; download evidence artifacts:
   ```bash
   gh run download <RUN_ID> --repo <consumer> -n <evidence-artifact-name> -D ./consumer-evidence/<consumer>/
   ```
5. Verify bundles with the OVK release verifier + cosign as applicable for the pin.
6. Exercise a true cross-fork PR path (`docs/FORK_PR.md` in each consumer).
7. Update the pilot ledger: keep `automated_scenario` rows distinct from human adjudications.

Local clone prep (optional, no push):

```bash
git clone https://github.com/fraware/ovk-consumer-fastapi-terraform.git
git clone https://github.com/fraware/ovk-consumer-express-actions.git
# Edit workflow pins locally; do not git push until maintainers cut rc.1.
```

## Sprint 9 checklist (per consumer) — prepare in this repo; land in consumer repos

In-repo preparation (this repository):

- [x] Document rc.1 target pins and provenance correction (this checklist + R2 status)
- [x] Keep human pilot ledgers separate from automated fixtures (see consumer `pilot/ledger.json` policy)
- [x] Template workflow targets `v1.3.0-rc.1` (copy only after tag exists)
- [ ] Cut attributable `v1.3.0-rc.1` tag on verified source (Sprint 10)

In consumer repositories (requires write access — **blocked from this workspace alone**):

- [ ] Bump Action pin from `v1.2.1` → `v1.3.0-rc.1` (or audited full SHA)
- [ ] Bump `OVK_PACKAGE_VERSION` / wheel install scripts to match
- [ ] Dispatch validation workflows; await conclusions
- [ ] Download evidence bundles; verify with release verifier + cosign as applicable
- [ ] Exercise true cross-fork PR path (`docs/FORK_PR.md`)
- [ ] Update ledger: automated scenarios remain distinct from human adjudications

## Checklist (per consumer) — ongoing

- [x] Workflow copies from `docs/templates/consumer_validation.workflow.yml` (or equivalent) with an immutable pin.
- [x] Automated scenario matrix covers program section 23.1 intents (see consumer README).
- [x] Adjudication rows recorded in a pilot ledger conforming to `schemas/pilot.ledger.schema.json`.
- [ ] Human adjudications reach 30 PRs (entries must not remain `automated_scenario` / `pending` only).
- [ ] True cross-fork PR exercised and ledger-adjudicated (see consumer `docs/FORK_PR.md`).
- [ ] Prefer PyPI once published; until then Release wheel + cosign verify-blob at the **current** pin.

## What this does not claim

- Declaring two independent consumer repos with 30 adjudicated PRs complete
- Vision completion or Production-stable package status
- That FormalPR-Holdout results generalize to these consumers (holdout is a separate program)
- That `v1.2.1` consumer green runs validate typed-control-plane `main`
