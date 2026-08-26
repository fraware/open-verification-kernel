# Consumer Validation Checklist

OVK uses two independent consumer repositories for candidate-pin and adoption evidence:

- `fraware/ovk-consumer-fastapi-terraform`
- `fraware/ovk-consumer-express-actions`

This program has two distinct phases that must not be conflated:

1. **pre-publication release authorization:** each consumer must pin the exact 40-hex OVK candidate SHA;
2. **post-publication adoption:** a consumer may later replace that full SHA with the immutable signed release tag after the attributable release exists.

Completing automated consumer scenarios is not equivalent to independent human calibration. The production exit criterion remains separate and requires the adjudication program described below.

## Why the pre-publication pin is a commit SHA

Release authorization must be causally possible **before** the GitHub Release is public. Therefore `Consumer Pin Verification` cannot require a tag whose publication depends on that same consumer evidence.

For the RC authorization run, consumer workflows must contain the exact candidate pin:

```yaml
steps:
  - uses: fraware/open-verification-kernel@<40-hex-candidate-sha>
```

The verifier requires the exact full SHA and rejects:

- `uses: ./`;
- `@main`, `@master`, or `@HEAD`;
- a historical tag such as `v1.2.1` as evidence for a new candidate;
- a semver tag in place of the candidate SHA for the pre-publication release-authorization artifact;
- any OVK ref that does not end in the exact candidate SHA supplied to the workflow.

The workflow also records the exact consumer checkout SHA and SHA-256 digests of consumer workflow files, so later authorization is tied to the consumer bytes that were actually inspected.

## Pre-publication candidate-bound evidence

Before running the release Publish workflow, prepare both consumer repositories so an auditable ref (for example `main` or a dedicated validation branch) pins the exact OVK candidate commit.

Then dispatch OVK's verifier on the same immutable OVK tag ref used for the rest of the release-evidence set:

```bash
export TAG='v1.3.0-rc.1'
export CANDIDATE_SHA='<exact 40-hex OVK candidate>'

gh workflow run consumer-pin-verification.yml \
  --repo fraware/open-verification-kernel \
  --ref "$TAG" \
  -f ovk_candidate_sha="$CANDIDATE_SHA" \
  -f fastapi_ref=main \
  -f express_ref=main
```

Use different consumer refs if candidate-pin changes are intentionally staged on validation branches. Whatever refs are supplied, the evidence artifact records both the requested ref and the exact resolved consumer source SHA.

Release authorization requires one successful `Consumer Pin Verification` run whose artifacts contain both required repositories. The live release authorizer downloads those exact artifacts from the selected run ID and verifies:

- expected consumer repository set;
- evidence schema;
- exact OVK candidate SHA;
- exact textual pin `fraware/open-verification-kernel@<candidate-sha>`;
- valid 40-hex consumer checkout SHA;
- non-empty, valid workflow-file SHA-256 digest set;
- no duplicate consumer repository evidence.

## Post-publication immutable tag adoption

After `v1.3.0-rc.1` is attributable and public, consumer repositories may choose to replace the candidate SHA with the immutable release tag for ordinary maintainability:

```yaml
env:
  OVK_PACKAGE_VERSION: "1.3.0-rc.1"

steps:
  - uses: fraware/open-verification-kernel@v1.3.0-rc.1
```

This post-release tag pin is adoption evidence. It is **not** retroactively substituted for the candidate-SHA artifact used to authorize the release.

Historical `v1.2.1` validation remains evidence only for the `v1.2.1` source/release. It must not be re-attributed to the RC control-plane tree.

## Consumer scenario validation

Each consumer should exercise, at minimum, scenarios relevant to its stack and documented support contracts, including:

- advisory allow/block behavior;
- strict block on a supported known-bad case;
- malformed/unsupported abstraction producing review/unknown rather than false allow;
- comment/check-run behavior under expected permissions;
- release-bundle generation and validation where applicable;
- installed wheel/action behavior outside the OVK checkout;
- cache behavior without cross-repository trust leakage;
- policy or metadata changes;
- backend unavailable/timeout behavior;
- generated regression artifacts and evidence-integrity checks.

Automated scenarios are useful engineering evidence, but they must remain labeled as automated fixtures rather than human adjudications.

## Cross-fork permissions boundary

Each consumer must also exercise a genuine fork-PR path before any claim of calibrated strict enforcement. Fork PR permissions differ from same-repository PR permissions; successful in-repo or same-repository dogfood does not prove comments/check-run writes work under reduced fork permissions.

Use the consumer's documented fork-PR procedure (for example `docs/FORK_PR.md`) and record the actual outcome in its pilot/adjudication ledger.

Do not replace `pull_request` with a privileged `pull_request_target` execution of untrusted PR code merely to obtain write permissions.

## Human adjudication program

Automated consumer verification is not the final external-calibration criterion. For production-stable claims, maintain the separate adjudication program:

- [ ] at least 30 human-adjudicated PRs per independent consumer, if that remains the governing project threshold;
- [ ] rows identify actual human adjudication rather than `automated_scenario` placeholders;
- [ ] false positives, false negatives, unknowns, and unsupported cases are retained rather than silently discarded;
- [ ] cross-fork behavior is included;
- [ ] calibration results are reported separately from FormalPR-Bench and FormalPR-Holdout;
- [ ] any strict-mode promotion is scoped to the exact lane/profile/input trust assumptions that were calibrated.

The threshold is a governance condition, not a statistical guarantee by itself. Any accuracy or generalization claim must still be proportionate to sample construction and observed evidence.

## Per-consumer release checklist

### Before attributable publication

- [ ] consumer repository/ref is explicitly selected;
- [ ] OVK Action pin is the exact candidate 40-hex SHA;
- [ ] `uses: ./` and mutable refs are absent;
- [ ] candidate-pin workflow is committed on the selected consumer ref;
- [ ] OVK `Consumer Pin Verification` is dispatched on the release candidate tag ref;
- [ ] both matrix jobs succeed;
- [ ] retained artifact records exact consumer source SHA and workflow digests;
- [ ] release ledger independently re-downloads and accepts both consumer artifacts.

### After attributable publication

- [ ] optionally replace the candidate SHA with the immutable signed release tag;
- [ ] align `OVK_PACKAGE_VERSION`/wheel installation with the published version where used;
- [ ] rerun consumer scenario validation on the published distribution/ref;
- [ ] verify Sigstore/release artifacts when the consumer uses the release wheel;
- [ ] exercise true cross-fork PR behavior;
- [ ] continue human adjudication separately from automated fixtures.

## What this evidence does not claim

Consumer-pin evidence does **not** establish:

- universal correctness of OVK;
- production-stable general enforcement;
- independent statistical calibration merely because two repositories exist;
- that FormalPR-Holdout generalizes to these consumer repositories;
- that historical `v1.2.1` consumer runs validate the new RC;
- that an immutable tag pin after publication can replace the exact candidate-SHA evidence required to authorize that publication.

Release ordering and the complete authority model are defined in [RELEASE.md](RELEASE.md) and [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md).