# OVK final technical release-closure record — 2026-08-26

This document is the dated closure addendum to `CURRENT_RELEASE_STATUS.md` for the final `1.3.0-rc.1` pre-tag engineering pass. It records what was actually established during the closure pass, the exact trust boundary of that evidence, and the remaining maintainer-only publication controls. Where an older status paragraph or unchecked development item conflicts with this dated record, this record is the later technical-closure evidence.

## Scope

This pass closed repository engineering, consumer integration, release-workflow correctness, evidence retention, pull-request hygiene, and branch hygiene. It does **not** manufacture release authority: an attributable public `v1.3.0-rc.1` still requires the signed tag, tag-bound evidence set, live release-ledger authorization, ref protection, signing, PyPI publication/read-back, and final GitHub Release transition defined by `RELEASE.md` and `ATTRIBUTABLE_PUBLICATION.md`.

## Candidate identity rule

The final candidate is the immutable kernel commit produced by merging the documentation PR that adds this record, before any later generated `[skip ci]` benchmark-badge provenance commit. A commit cannot embed its own SHA without a circular dependency, so the exact final candidate SHA is recorded in the merged PR discussion and in the candidate-bound consumer verification evidence after this file lands.

Generated benchmark badge commits do not redefine the candidate. Their `benchmark_source_sha` identifies the source tree that was measured.

## Technical closure completed before this record

The closure pass established all of the following without re-attributing historical release evidence:

1. Release-workflow dispatch contracts were repaired and regression-tested. `workflow_dispatch` inputs are explicitly typed and external workflow/action references are checked for exact 40-hex immutable pins.
2. The two independent consumer repositories were migrated from the superseded candidate to the then-current kernel candidate, with candidate-aware pin guards and candidate-aware scenario source assertions while retaining the independently signed published `1.2.1` wheel for historical scenario execution.
3. Both consumer PRs were validated on their exact heads and merged to `main`:
   - `fraware/ovk-consumer-fastapi-terraform` merged source: `d547172095a26af4e2d7d3bd46b19c10ee77a05d`.
   - `fraware/ovk-consumer-express-actions` merged source: `5f6d201d9c1a32e7430229efdaf51f84457c79ce`.
4. The central `Consumer Pin Verification` workflow was proven dispatchable. A fresh merged-consumer run then exposed an evidence-retention defect rather than a pin defect: evidence was generated under `.verification/`, while `actions/upload-artifact` excluded hidden files by default.
5. PR #28 fixed that defect by explicitly enabling hidden-file upload and added a regression test requiring the `.verification/` path, `if-no-files-found: error`, and `include-hidden-files: true`.
6. PR #28 exact-head validation passed the full CI workflow and complete six-cell Repro baseline before merge.
7. After PR #28 merged, central Consumer Pin Verification run `33013887961` completed successfully for both consumer `main` branches, including exact candidate-pin assertion, ledger-ready evidence generation, and evidence upload.
8. That run retained two non-expired artifacts. The artifact payloads bind the exact consumer checkout SHAs listed above to the tested kernel candidate and include SHA-256 digests of the relevant consumer workflow files.

The final candidate produced by this documentation merge must now replace the earlier kernel SHA in both consumer repositories. That one final repin is required because the eventual release tag must contain the repaired release-evidence workflow from PR #28 and this closure documentation. After that repin, the complete exact-candidate development/evidence matrix must be rerun against the frozen SHA; no older green run is substituted for that final evidence.

## Required final freeze sequence

After this document is merged, the technical closure sequence is:

1. Record the documentation merge commit as the final candidate SHA.
2. Repin both consumer repositories to that exact 40-hex SHA and merge only after their full candidate-bound PR validation succeeds.
3. Run the kernel exact-candidate matrix on the frozen SHA: CI, six-cell Repro baseline, Native Backends Tier 1, and Native Backends Tier 1b.
4. Run central Consumer Pin Verification against the two merged consumer `main` branches and the frozen candidate SHA.
5. Require both consumer matrix jobs to succeed and require both retained evidence artifacts to exist; inspect their payloads and confirm the expected consumer source SHAs and exact kernel pin.
6. Remove all non-`main` branches in the kernel and both consumer repositories after proving their intended content is merged or intentionally obsolete.
7. Verify zero open PRs and exactly one active branch (`main`) in each of the three repositories.
8. Record the exact final candidate SHA, consumer merge SHAs, workflow run IDs, artifact identities/digests, and final branch/PR inventory in the closure PR discussion.

No source, workflow, or documentation change should be merged into the candidate after step 1. A later generated benchmark-badge provenance commit is explicitly non-candidate metadata and must not be silently substituted for the frozen SHA.

## Evidence boundaries

The engineering evidence above establishes repository-level correctness and reproducibility only within the documented assumptions and trust boundaries. It does not establish universal formal verification, external accuracy calibration, production-stable strict enforcement for arbitrary repositories, or independent human validation.

FormalPR-Bench remains an internal curated regression suite. Native backend guarantees remain bounded by the exact compiler/input/tool assumptions documented in `BACKENDS.md`. Consumer repositories provide independent integration surfaces, but they are maintained within the same broader project context and therefore must not be misrepresented as independent external scientific replication.

## Publication controls intentionally not waived

The following are separate from repository technical closure and remain mandatory for an attributable public release:

- protect `main` against force-push/deletion and protect the release-tag namespace against mutation/deletion;
- create the signed annotated release tag at the frozen candidate SHA;
- execute the complete tag-bound workflow set required by `CURRENT_RELEASE_STATUS.md` and `RELEASE.md`;
- obtain live release-ledger authorization and a `verified_source_sha` from the authoritative verifier rather than entering one manually;
- bind exact wheel/sdist bytes, complete Sigstore signing/verification and tamper checks, stage the private GitHub Release, publish through PyPI Trusted Publishing, verify exact PyPI filenames and SHA-256 values, and only then make the GitHub Release public.

At the time this closure record was authored, GitHub reported `main` as unprotected and the repository ruleset collection as empty. That condition is not converted into a pass by this document. Issue #25 remains the administrative control record until protection is configured and verified live.

## Closure standard

The repository is considered technically closed for this engineering pass only when the final freeze sequence above is evidenced on one immutable candidate and the repository surface has been reduced to `main` with no open PRs. Publication readiness is a stricter state and additionally requires every maintainer/publication control above.
