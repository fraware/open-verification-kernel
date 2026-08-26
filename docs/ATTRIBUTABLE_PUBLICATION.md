# Attributable Publication Checklist

This document defines the evidence threshold for publishing **`v1.3.0-rc.1`** and for any later production promotion. The executable maintainer procedure is [RELEASE.md](RELEASE.md); this file is the corresponding trust checklist.

Authority surfaces:

- release procedure: [RELEASE.md](RELEASE.md)
- current status: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)
- trusted computing base: [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md)
- holdout governance: [FORMALPR_HOLDOUT_GOVERNANCE.md](FORMALPR_HOLDOUT_GOVERNANCE.md)
- consumer evidence: [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md)

## Authority model

Two source identities are intentionally distinct:

| Field | Meaning | Authority |
|---|---|---|
| `benchmark_source_sha` | Commit whose benchmark/badge artifacts were measured | Benchmark execution only |
| `verified_source_sha` | Exact commit authorized for release after all required live provenance is independently checked | Release ledger only |

`verified_source_sha` is **not** a maintainer-entered status field. It must never be copied from a badge, PR run, benchmark result, holdout report, consumer fixture, or prose document. It is minted only by `scripts/verify_release_ledger_github.py` after full authorization succeeds.

The input ledger must remain unauthorized: `authorized=false`, `verified_source_sha=null`, `published=false`, `tag=null`. Offline structural validation cannot grant release authority.

## Pre-tag engineering gate

Before creating an immutable tag, require the exact final candidate commit to pass the ordinary development matrix:

- [ ] CI, including lint, unit/integration tests, release preflight, package smoke, Action dogfood, and template conformance;
- [ ] Repro baseline on Linux/macOS/Windows × Python 3.10/3.12;
- [ ] Native Backends Tier 1;
- [ ] Native Backends Tier 1b;
- [ ] package metadata, `ovk.__version__`, and release metadata agree;
- [ ] generated capability tables, project status, benchmark registries, and TCB document are fresh;
- [ ] FormalPR-Bench claims remain explicitly regression-only, not external calibration;
- [ ] public documentation describes unsupported/experimental paths proportionately.

These checks are necessary but **not sufficient** for publication. PR/push runs are development evidence and are not reused as final release authorization.

## Immutable candidate identity

Create exactly one signed annotated tag for the frozen candidate. For this RC:

```text
package version: 1.3.0-rc.1
tag:             v1.3.0-rc.1
```

Required properties:

- [ ] tag is annotated, not lightweight;
- [ ] GitHub reports the tag signature as verified;
- [ ] tag points directly to one commit;
- [ ] direct target equals the exact release candidate SHA;
- [ ] tag version exactly matches package release metadata;
- [ ] historical tags are not moved or re-attributed;
- [ ] live repository settings protect the release-tag namespace against update and deletion after tag creation;
- [ ] `main` is protected against force-push and deletion by branch protection or an active equivalent ruleset.

Ref protection is defense in depth, not a substitute for cryptographic identity checks. The release authorizer must still resolve and verify the annotated tag object and direct candidate target on every authorization run. Repository-setting evidence must be checked live; documentation cannot self-assert that the protection exists.

The production Publish workflow must itself be dispatched on `refs/tags/<tag>`. Checking out a tag from a branch-bound workflow is not equivalent because the Sigstore workflow identity would remain branch-bound.

## Seven required tag-bound release-evidence workflows

Final authorization requires successful **`workflow_dispatch`** runs on the immutable tag for exactly these release surfaces:

1. `CI`
2. `Repro baseline`
3. `Native Backends Tier 1`
4. `Native Backends Tier 1b`
5. `FormalPR-Holdout predict`
6. `FormalPR-Holdout eval`
7. `Consumer Pin Verification`

The collector may draft candidate-bound observations, but it cannot authorize them. The network-backed authorizer independently re-fetches every selected run ID and checks repository, workflow name/path, event, candidate `head_sha`, completion state, and successful conclusion.

## Holdout evidence boundary

Prediction and evaluation remain label-separated.

The prediction workflow:

- [ ] runs without the holdout download credential;
- [ ] emits label-free predictions only;
- [ ] records `candidate_source_sha`;
- [ ] emits a manifest binding the exact predictions SHA-256;
- [ ] does not contain or mint `verified_source_sha`.

The evaluation workflow:

- [ ] consumes the prediction artifact from an explicit prior prediction **run ID**;
- [ ] checks the prediction candidate identity before label access;
- [ ] recomputes and matches the prediction-file SHA-256 against the prediction manifest;
- [ ] verifies the frozen holdout release-asset SHA-256;
- [ ] strips download credentials after acquisition;
- [ ] emits aggregate-only public evidence;
- [ ] binds candidate SHA, prediction digest, holdout-asset digest, holdout tag, and aggregate digest;
- [ ] does not contain or mint `verified_source_sha`.

A missing, malformed, substituted, expired, or mismatched artifact must fail authorization.

## Independent consumer evidence

Both required consumer repositories must provide candidate-bound evidence:

- `fraware/ovk-consumer-fastapi-terraform`
- `fraware/ovk-consumer-express-actions`

For each consumer, require:

- [ ] exact 40-hex OVK candidate pin;
- [ ] no `uses: ./` substitution;
- [ ] exact consumer checkout SHA;
- [ ] retained workflow-file SHA-256 digests;
- [ ] successful `Consumer Pin Verification` artifact from the tag-bound release-evidence run.

Consumer evidence demonstrates that independent repositories pin the exact candidate. It does not by itself establish broad external calibration or production-stable accuracy.

## Distribution authorization

The release authorizer must build and bind exactly one wheel and one sdist. Authorization requires:

- [ ] exact candidate repository/SHA identity;
- [ ] complete live workflow provenance;
- [ ] complete holdout artifact provenance;
- [ ] complete consumer artifact provenance;
- [ ] exact wheel filename and SHA-256;
- [ ] exact sdist filename and SHA-256;
- [ ] no P0 blocker recorded by the authorized ledger.

After authorization, every later release job rechecks the local distribution bytes against the authorized ledger before signing, staging, or publishing them.

## Sigstore identity

The wheel, sdist, and authorized release ledger are keyless-signed and verified in the protected `sigstore` environment.

Exact issuer:

```text
https://token.actions.githubusercontent.com
```

Exact production identity pattern:

```text
https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/vX.Y.Z
```

Required evidence:

- [ ] workflow is tag-ref bound;
- [ ] exact certificate identity and issuer are used for verification;
- [ ] same-workflow verification succeeds for every signed artifact;
- [ ] mutated copies fail verification;
- [ ] cosign bundles and signing summary are retained.

Branch-bound Sigstore runs are not production release evidence.

## Publication ordering

A public GitHub Release must never be an input to authorization. The only permitted production order is:

```text
signed annotated tag
  -> tag-bound release-evidence runs
  -> live release-ledger authorization
  -> exact distribution recheck
  -> Sigstore sign / verify / tamper test
  -> private GitHub Release draft
  -> PyPI Trusted Publishing
  -> independent exact PyPI filename + SHA-256 verification
  -> make the existing GitHub Release public
```

Do **not** manually run `gh release create` before Publish. `.github/workflows/publish.yml` owns the draft/public transition.

## PyPI and recovery policy

PyPI uses OIDC Trusted Publishing in the protected `pypi` environment. Long-lived PyPI password/API-token authentication is not part of the production workflow.

Before publication, the only acceptable remote states are:

- `absent`: first publication may proceed;
- `exact_match`: a recovery run may proceed because PyPI already exposes exactly the authorized filenames and SHA-256 values.

`conflict` is fatal. Missing files, extra files, duplicate filenames, malformed digests, or any digest substitution fail closed. Blind `skip-existing` recovery is not permitted.

After Trusted Publishing, PyPI must be `exact_match`; `absent` is no longer acceptable. Only after that independent read-back succeeds may the GitHub Release transition from draft to public.

If PyPI succeeds and final GitHub publication fails, rerunning on the same immutable tag is permitted only after exact PyPI equality is re-established. If a GitHub Release for the tag is already public, Publish refuses to mutate it.

## Claims allowed before and after authorization

Before the ledger authorizes the candidate:

- benchmark artifacts may cite `benchmark_source_sha`;
- development CI may be described as green on its exact SHA;
- the package may be described as an engineering/release candidate;
- `verified_source_sha` must remain unset;
- the RC must not be described as an attributable published release.

After full authorization and publication:

- the authorized ledger may identify `verified_source_sha`;
- the published wheel/sdist may be attributed to that exact source SHA and Sigstore identity;
- benchmark scores remain internal-regression evidence unless separate external calibration has actually been completed.

## Promotion beyond the RC

Promotion to a production-stable `v1.3.0` claim additionally requires the project’s independent-validation conditions, including consumer/adjudication and governed holdout evidence. Automated fixtures, in-repository dogfood, or internal benchmark success must not be relabeled as independent human calibration.

## Final maintainer checklist

- [ ] exact final candidate passes the complete development matrix;
- [ ] `main` and the release-tag namespace have live verified ref protection;
- [ ] signed annotated immutable tag exists and is GitHub-verified;
- [ ] all seven required release-evidence workflows succeed as tag-bound `workflow_dispatch` runs;
- [ ] label-free prediction → exact-run evaluation handoff is retained and digest-bound;
- [ ] both consumer artifacts pin the exact candidate;
- [ ] live authorizer produces an authorized v2 ledger and alone mints `verified_source_sha`;
- [ ] wheel and sdist hashes equal the authorized ledger;
- [ ] tag-bound Sigstore verification and tamper tests pass;
- [ ] GitHub Release remains draft until PyPI exact verification succeeds;
- [ ] PyPI exposes exactly the authorized distribution set;
- [ ] public GitHub Release is made visible only after the previous condition;
- [ ] release notes and status documents report only evidence actually obtained.

For exact commands and recovery procedure, follow [RELEASE.md](RELEASE.md).