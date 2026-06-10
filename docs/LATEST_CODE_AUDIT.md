# Latest Code Audit

Date: 2026-06-10

This audit reviews the current `main` branch after the latest engineer pushes. It compares the current repository state with the prior release-hardening baseline and evaluates whether OVK is closer to the intended vision: a solver-agnostic verification kernel for AI-agent engineering workflows.

## Scope

The current branch contains a large post-baseline expansion. The most important new areas are:

- v1.2.0 package metadata and release documentation;
- expanded GitHub Actions workflows;
- a much larger composite GitHub Action;
- five check lanes instead of three;
- `ovk check`, `ovk run`, `ovk verify`, `ovk release-bundle`, `ovk release-preflight`, `ovk evidence-quality`, and related commands;
- a kernel orchestration layer for inference, ranking, routing, compilation, execution, and decisioning;
- native backend probes and fallback adapters;
- FormalPR-Bench expansion and realistic diff fixtures;
- release bundles with evidence, Markdown, attestation, manifest, evidence quality, provenance, and attestation envelope artifacts;
- external-pilot and rollout documentation.

## Executive judgment

The repo has made a major leap toward the OVK vision. It is no longer only a three-lane local runner prototype. It now resembles a real verification product surface with an installable package, composite Action, multi-lane kernel, benchmark suite, release bundle, preflight gate, and five check types.

The strongest current claim is that OVK has become a practical local and CI-oriented evidence generator for high-risk AI-agent pull requests. The weakest current claim is that OVK is already production-stable as a fully automated GitHub-native enforcement platform. The codebase is much closer to that vision, but a few important correctness and positioning issues remain.

## What looks strong

### 1. The kernel architecture is now real

The new kernel path introduces a coherent flow:

1. build a plan from changed files or diff text;
2. build repository context;
3. rank candidate intents;
4. route intents to candidate backends;
5. compile obligations;
6. execute obligations;
7. create a content-addressed evidence bundle;
8. render Markdown and release artifacts.

This is the right architectural direction. It moves OVK closer to the intended kernel model rather than a collection of independent scripts.

### 2. Five check lanes are now integrated

The current command surface and docs include five core lanes:

- self-protection;
- authorization;
- infrastructure exposure;
- CI secrets exposure;
- deployment approval state.

This is a meaningful improvement over the prior state. It makes the product narrative much more credible for AI-agent pull requests because it covers multiple real failure surfaces.

### 3. Release bundle infrastructure is substantially better

The release bundle writer now emits:

- evidence bundle;
- PR Markdown;
- attestation statement;
- artifact manifest;
- evidence quality report;
- provenance statement;
- attestation envelope.

The verifier checks required artifacts, manifest hashes, envelope signatures when present, attestation binding, and envelope-manifest binding. This is a strong release-hardening step.

### 4. Evidence-quality checks are now first-class

Evidence-quality reporting is no longer a side idea. The current repo includes:

- invariant checks;
- JSON quality reports;
- CLI command support;
- runner output integration;
- manifest inclusion for quality reports;
- adversarial quality-gate preflight.

This directly supports the core trust loop: OVK should not only produce evidence but also check whether its own evidence is internally coherent.

### 5. The composite Action is far more mature

The Action now supports:

- advisory and strict mode;
- `ovk check` path;
- manifest-driven `ovk verify` path;
- self-protection `ovk ci` path;
- quality report generation;
- GitHub check emission;
- PR comment posting;
- artifact upload;
- branch metadata collection;
- action outputs for recommendation, exit code, and check emission.

This is a large step toward real GitHub-native usage.

### 6. The benchmark story is much stronger

The repo now includes expanded FormalPR-Bench cases, realistic PR diffs, all-lane scoring, leaderboard artifacts, badge automation, pilot manifests, and external validation scaffolding. This is an important move from demo to measurable system.

## High-priority findings

### Finding 1: `ovk check` still has nondeterministic evidence ordering in parallel execution

The lower-level obligation runtime currently appends parallel results in completion order. This can change the ordering of evidence items across runs. Since bundle IDs are content-addressed over ordered evidence payloads, this can make bundle IDs, manifests, and attestation chains nondeterministic for multi-obligation `ovk check` runs.

Impact: high for reproducibility and release integrity.

Status: partially fixed. During this audit, manifest-driven verification was patched to preserve lane order during parallel execution. The analogous patch for `ovk.core.adapter_runtime.execute_obligations` was attempted but blocked by connector controls.

Required fix:

- map each future to its original obligation index;
- collect results by index;
- return evidence in original obligation order;
- add a regression test similar to `tests/test_multi_lane_order.py` for `execute_obligations`.

### Finding 2: Latest HEAD is a `[skip ci]` badge commit, so current CI status is not observable from the current SHA

The docs claim a strong health state, including passed tests and release checks. The latest HEAD is a GitHub Actions bot commit marked `[skip ci]`, and no workflow runs are attached to that commit through the connector.

Impact: medium to high for release claims.

This does not mean CI failed. It means the latest commit cannot independently substantiate the release-readiness claims from observable GitHub status. A maintainer should provide or inspect the previous CI run that produced the badge and test count before treating the release claims as externally validated.

Required action:

- identify the last non-skip CI commit;
- confirm the CI workflow passed there;
- link that run in release notes or status if making strong release claims;
- avoid treating the badge-update commit as the release verification point.

### Finding 3: Release positioning may be ahead of independently verified maturity

`pyproject.toml` now marks the package as `Development Status :: 5 - Production/Stable`, and the docs present v1.2.0 as the current release. This may be appropriate if the maintainers have verified the CI and external pilot claims, but from this audit the strongest independently supported position is that the repo has an ambitious v1.2.0 release surface with strong local and CI definitions.

Impact: medium.

Required action:

- confirm v1.2.0 tag and release publication status;
- confirm PyPI publication status;
- confirm external validation results;
- decide whether `Production/Stable` is the intended classifier or whether `Beta` is more accurate until external adopters complete rollout.

### Finding 4: Preflight schema drift was present and has been patched

The preflight report model emits `messages` and supports `optional_checks`. The schema previously documented `failures` and did not explicitly model `optional_checks`. This audit patched `schemas/preflight.report.schema.json` to match the emitted payload shape.

Impact: fixed.

### Finding 5: Native backend language must remain honest

The backend docs and workflows describe ten formal backends and required Tier 1 native checks. The implementation is careful in several places to use deterministic fallbacks and to record native execution status. However, not all adapters appear to perform full native proof or model-check execution. Some validate binary presence or use deterministic fixture oracles.

Impact: medium for trust and marketing accuracy.

Required action:

- keep docs explicit that some backends are contract/probe/fallback adapters;
- avoid implying full formal verification for CBMC, Lean, Dafny, Verus, Alloy, Kani, and TLA+ until native harnesses are implemented;
- make every native backend evidence artifact state whether a native binary actually contributed to the decision.

### Finding 6: Action shell construction should be hardened

The composite Action builds shell variables from inputs such as `check-metadata`. These are usually workflow-author-controlled, but hardening would still be appropriate.

Impact: medium for robust external adoption.

Required action:

- avoid building shell command fragments with unquoted input strings;
- prefer direct arrays or explicit branches;
- validate input paths before passing them to commands;
- keep PR-controlled values out of shell expansion.

### Finding 7: Release layout helpers are split between default layout and bundle layout

`ovk.core.release_layout.default_release_layout` still models a smaller artifact set, while `ovk.core.release_bundle.release_bundle_layout` includes evidence quality, provenance, and attestation envelope artifacts. Runtime uses the release-bundle layout for bundle verification, so this is not an immediate bug. It is a maintainability risk because there are two nearby concepts with different artifact expectations.

Impact: low to medium.

Required action:

- either deprecate the old default layout helper;
- or make it explicitly a minimal layout;
- or consolidate layouts into one source of truth with profiles.

## Patch applied during this audit

### Patch 1: Manifest-lane parallel execution order

`ovk.core.multi_lane.run_verification_manifest` was updated so parallel manifest execution preserves the order of manifest lanes rather than completion order.

### Patch 2: Manifest-order regression test

`tests/test_multi_lane_order.py` was added to ensure that a slower first lane and faster second lane still produce evidence in manifest order.

### Patch 3: Preflight schema alignment

`schemas/preflight.report.schema.json` was updated to document `messages` and `optional_checks`, matching `PreflightReport.to_dict()`.

## Vision achievement assessment

### Achieved

OVK now demonstrates the core loop:

- infer relevant checks from PR surfaces;
- route checks to appropriate lanes/backends;
- compile lane inputs or obligations;
- generate normalized evidence;
- decide allow/block/review;
- render review artifacts;
- emit release bundles;
- check evidence quality;
- run preflight and benchmark gates.

This is a major architectural milestone.

### Not fully achieved

The full vision also requires:

- deterministic release artifacts across all parallel execution paths;
- externally validated GitHub Action usage;
- honest and precise native backend claims;
- complete CLI/script parity;
- real external pilot metrics;
- schema coverage for every generated artifact;
- native backend execution depth beyond deterministic or contract probes;
- clear release provenance for the claims in status docs.

## Current release judgment

Current status: advanced v1.2.0 release candidate, pending verification of CI run provenance and external adoption claims.

If maintainers can show the CI run behind the reported test and benchmark numbers, the repository is close to a credible v1.2.0 release. Without that verification, the current docs are somewhat stronger than what the latest observable commit can prove.

## Questions for engineers

1. Which commit or workflow run produced the `374 passed, 12 skipped` claim?
2. Was the latest `[skip ci]` benchmark badge commit intentionally made after a green CI run?
3. Is `Development Status :: 5 - Production/Stable` intentional, or should the classifier remain Beta until external pilots complete?
4. Do Tier 1 native backend checks require actual native verification, or is binary/probe plus deterministic oracle acceptable for v1.2.0?
5. Should `ovk check` bundle IDs be guaranteed reproducible across parallel runs? If yes, the `adapter_runtime` order fix is mandatory.
6. Should release notes claim strict mode is safe today, or should they frame strict mode as safe after advisory calibration on a target repository?

## Recommended next steps

### Immediate engineer tasks

1. Fix deterministic ordering in `ovk.core.adapter_runtime.execute_obligations`.
2. Add a regression test for adapter-runtime ordering.
3. Confirm and document the CI run that backs the release-status metrics.
4. Review backend documentation for native-execution accuracy.
5. Harden Action shell input handling.

### Next product tasks

1. Run a real external consumer workflow using `uses: fraware/open-verification-kernel@v1.2.0`.
2. Record advisory pilot metrics in the pilot case studies.
3. Add provenance links from release notes to CI runs and benchmark artifacts.
4. Decide whether optional native backends should stay informational until full harness execution exists.

## Bottom line

The engineers pushed a very substantial and mostly directionally correct expansion. The repository is much closer to the intended OVK vision than before. The biggest remaining concern is not feature absence; it is the need to ensure determinism, claim accuracy, and external validation match the now-ambitious release surface.
