# Current Work Assessment

This assessment summarizes the current state of Open Verification Kernel after the Sprint 5, Sprint 6, and Sprint 7 release-hardening work.

## Executive assessment

OVK has moved from a concept prototype into a credible v0.1 release candidate for local and repository-internal verification workflows. The project now has three usable evidence lanes, a shared artifact-output layer, release metadata checks, local preflight checks, structured preflight reporting, artifact manifests, attestation envelopes, and an evidence-quality gate. The core vision is now visible in code: engineering changes can be mapped into verification evidence, normalized into bundle-level decisions, rendered into review artifacts, and checked for release consistency.

The current system is not yet a fully automated GitHub-native enforcement platform. The strongest parts of the repository are the evidence model, local runners, artifact generation, release preflight, infrastructure exposure lane, authorization lane, and evidence-quality layer. The weakest parts are GitHub Action hardening, first-class CLI parity across all runner features, full self-protection integration into the local smoke path, and direct CI observability.

## Current capability state

### Self-protection lane

The self-protection lane protects the core OVK threat model: an AI agent or automation should not be able to weaken, remove, or bypass the checks that constrain it. The lane has deterministic evaluation logic, CI-oriented metadata normalization, backend-strategy plumbing, and action-level integration primitives. It is mature enough as a local and CI-path concept, but it remains less integrated into the newest release-hardening flow than the authorization and infrastructure lanes.

Current maturity: usable but not fully release-hardened.

Remaining work:

- add self-protection to the local release smoke path;
- ensure self-protection output goes through the same evidence-quality report layer as infrastructure;
- improve GitHub Action path handling for external repositories;
- confirm live branch-protection metadata behavior in an external repository.

### Authorization obligation lane

The authorization lane has a strong architecture for v0.1. It includes an obligation model, deterministic path, optional Z3 execution path, validation, evidence normalization, regression generation, CLI and script surfaces, and benchmark scoring. It is one of the most conceptually important lanes because it demonstrates the translation from a security-relevant change into a formal or semi-formal obligation.

Current maturity: strong v0.1 lane, local-runner ready.

Remaining work:

- add manifest and evidence-quality report emission directly to the authorization runner;
- validate malformed inputs before obligation construction everywhere;
- add stronger tests for `unknown` and validation paths;
- add release-bundle output parity with the infrastructure lane.

### Infrastructure exposure lane

The infrastructure exposure lane is currently the most release-hardened lane. It supports native OVK infrastructure input, Terraform-plan-style input, Kubernetes Service-style input, policy configuration, evidence generation, regression artifacts, direct artifact manifests, and direct evidence-quality reports. It is the best current demonstration of the full release artifact loop.

Current maturity: strongest v0.1 lane.

Remaining work:

- expand the Terraform and Kubernetes normalizers while preserving conservative scope;
- wire graph-style normalization into the supported runner path if connector controls allow;
- add more policy fixtures and schema examples;
- add an end-to-end release-bundle example built from this lane.

## Release-hardening state

### Package and release metadata

Package metadata is aligned to version `0.1.0`. Import-time package versioning derives from release metadata. The repository has scripts to check package metadata, release metadata, and command-surface consistency before tagging.

Current maturity: release-ready for local checks.

Remaining work:

- move the command-surface check from source-text matching to Typer command inspection if practical;
- add CI execution for metadata and command-surface checks once workflow edits are stable;
- keep release notes synchronized with actual supported commands.

### Artifact manifest and attestation

OVK now produces deterministic artifact manifests with SHA-256 digests and byte sizes. It also has an attestation-envelope layer that binds attestation statements to manifest digests. This establishes a credible chain of release artifacts, although signatures and provenance integration are not yet implemented.

Current maturity: strong local release artifact layer.

Remaining work:

- add signed attestations or Sigstore-style provenance;
- add a single release-bundle command that emits evidence, Markdown, attestation, manifest, envelope, and quality report together;
- add manifest verification tooling that recomputes and checks artifact hashes;
- add release artifact layout checks once connector controls allow the script and tests.

### Preflight checks

OVK now has both a simple release preflight script and a structured preflight-report path. The preflight covers release metadata, command-surface consistency, and local smoke checks for authorization and infrastructure. The structured report can emit JSON for release archives.

Current maturity: useful local preflight, not yet full release gate.

Remaining work:

- integrate evidence-quality checks into preflight output;
- add self-protection to local smoke coverage;
- make the structured report the primary preflight path once migration is possible;
- add a preflight artifact to the standard release bundle.

### Evidence quality gate

Sprint 7 introduced evidence invariants and evidence-quality reports. The system can now reject or report evidence bundles with empty evidence, duplicate evidence IDs, missing backend claims, missing merge recommendations, unsafe allow recommendations, and unknown or error claims without human review. The infrastructure runner now emits evidence-quality reports directly, and standard manifests can include those reports as `evidence_quality` artifacts.

Current maturity: strong architectural step, early integration.

Remaining work:

- run evidence-quality checks automatically inside release preflight;
- add first-class evidence-quality outputs to all runners;
- add schemas for evidence-quality reports and invariant issues;
- decide whether evidence-quality failure should always override bundle recommendations.

## Engineering quality assessment

### Strengths

The repository now has a coherent internal architecture around evidence generation, artifact writing, preflight checking, and quality reporting. The codebase increasingly avoids duplicated serialization and output logic through shared helpers such as standard output writers, standard artifact helpers, JSON I/O helpers, release metadata helpers, preflight report helpers, and evidence-quality helpers.

The project has also preserved a conservative security posture. Invalid inputs generally lead to review instead of allow. Unknown or error states are increasingly treated as conditions that require human review. The evidence invariant engine formalizes this posture in a way that can become CI-enforceable.

Documentation has improved substantially. The repository now has release notes, tagging checklists, health checklists, preflight addenda, current release status, evidence invariant documentation, and evidence-quality report documentation.

### Weaknesses

The codebase still has uneven integration depth. Infrastructure is ahead of authorization and self-protection in release artifact support. Some first-class CLI commands lag behind the standalone scripts. Some central status documents are stale because repeated connector-control blocks forced addenda instead of clean rewrites.

The GitHub Action path is still weaker than the local-runner path. The repository does not yet have a fully validated external-repository workflow where OVK can be used as a drop-in action with correct path handling, branch metadata collection, PR comments, artifact uploads, and enforcement semantics.

The release process is stronger locally than in CI. Several checks exist as scripts and pytest tests, but observed GitHub status checks remain unavailable through the connector. A v0.1 tag should not claim full CI enforcement until this has been verified outside the connector limitations.

## Exact remaining sprints

### Sprint 7B: Evidence quality integration

Goal: make evidence-quality checking part of every release-critical path.

Steps:

1. Add `quality_report` output support to authorization runner.
2. Add `quality_report` output support to self-protection CI path if the shared output layer can be safely applied.
3. Add evidence-quality checks into `scripts/release_preflight_report.py` or a new non-blocked preflight adapter.
4. Add JSON schema for `ovk.evidence_quality.v1`.
5. Add tests that failing evidence-quality reports fail the checker and release preflight.
6. Update `docs/EVIDENCE_QUALITY_REPORT.md`, `docs/CURRENT_RELEASE_STATUS.md`, and Sprint 7 status notes.

Exit criteria:

- all three lanes can emit quality reports;
- quality reports are hash-addressed in manifests where generated;
- release preflight includes evidence-quality validation;
- no evidence bundle with invariant errors can be treated as release-ready.

### Sprint 8: Unified release bundle

Goal: produce a single repeatable release artifact bundle for any lane.

Steps:

1. Implement a release-bundle writer that orchestrates evidence, Markdown, attestation, manifest, quality report, and attestation envelope.
2. Add a bundle layout object with required and optional artifacts.
3. Add a bundle verification script that checks all expected artifacts exist.
4. Add manifest verification by recomputing hashes.
5. Add tests for a complete infrastructure release bundle.
6. Extend authorization release bundle support.
7. Document the release bundle command and expected layout.

Exit criteria:

- one command can create a complete local release bundle;
- the bundle can be verified locally;
- artifact manifests include evidence-quality reports;
- attestation envelopes bind to the manifest digest.

### Sprint 9: CLI parity and command consolidation

Goal: reduce the gap between scripts and first-class `ovk` commands.

Steps:

1. Refactor CLI commands to use shared JSON I/O, output writers, and exit-code helpers.
2. Add first-class CLI options for infrastructure `--input-format`, `--policy`, `--manifest-output`, and `--quality-output`.
3. Add authorization CLI support for manifest and quality output.
4. Add `ovk release-preflight` and `ovk evidence-quality` commands.
5. Replace source-text command-surface checks with Typer command inspection if feasible.
6. Update release metadata to distinguish first-class commands from standalone scripts.

Exit criteria:

- documented commands match actual CLI commands;
- script-only functionality is either promoted to CLI or clearly marked as script-only;
- release metadata is machine-checkable against the CLI.

### Sprint 10: GitHub Action hardening

Goal: make OVK usable as a real external-repository GitHub Action.

Steps:

1. Fix action path handling so scripts run from `${{ github.action_path }}` where necessary.
2. Add branch metadata collection through GitHub API with safe fallbacks.
3. Add optional PR comment posting with clear permission requirements.
4. Add artifact upload for evidence, Markdown, attestation, manifest, quality report, and preflight report.
5. Add advisory and enforcement modes with precise exit behavior.
6. Create a minimal external smoke repository or example workflow.
7. Document required GitHub token permissions.

Exit criteria:

- OVK can be used from another repository through `uses: fraware/open-verification-kernel@...`;
- action outputs are uploaded as artifacts;
- PR comment mode works when permissions are supplied;
- advisory and enforce modes are tested in an external repo.

### Sprint 11: Backend depth and formal assurance

Goal: deepen the verification substance behind the evidence claims.

Steps:

1. Strengthen the optional Z3 backend with more expressive authorization obligations.
2. Add solver-result provenance in evidence artifacts.
3. Expand OPA policy execution beyond optional self-protection comparison.
4. Add SMT plan artifacts to authorization evidence where useful.
5. Add counterexample minimization and deterministic regression generation across lanes.
6. Add explicit backend capability negotiation before execution.

Exit criteria:

- evidence claims clearly state whether they come from deterministic checks, OPA, Z3, or other backends;
- optional formal backends produce auditable artifacts;
- failure examples can be converted into regression tests consistently.

### Sprint 12: Benchmark and adversarial corpus

Goal: turn OVK into a measurable benchmark target, not just a library.

Steps:

1. Expand FormalPR-Bench with cases for self-protection, authorization, infrastructure, and evidence-quality failures.
2. Add malformed-input cases for every lane.
3. Add expected recommendation files for each benchmark case.
4. Add benchmark scoring scripts that run through the same runner paths as users.
5. Add benchmark summaries as release artifacts.
6. Add adversarial cases where evidence claims disagree with recommendations.

Exit criteria:

- benchmark cases cover pass, fail, unknown, malformed, and adversarial evidence;
- benchmark scoring becomes part of preflight or CI;
- OVK can report its own regression score before release.

### Sprint 13: Evidence schema governance

Goal: make evidence formats stable enough for external users.

Steps:

1. Add schemas for evidence-quality reports, preflight reports, release bundles, and invariant issues.
2. Add schema validation to all generated JSON outputs.
3. Add schema version migration notes.
4. Add backwards-compatibility tests for v0.1 artifacts.
5. Add examples for each schema.
6. Add a schema index document.

Exit criteria:

- every generated JSON artifact has a schema;
- every schema has a valid example;
- generated outputs are validated before release.

### Sprint 14: v0.1 release finalization

Goal: create a credible v0.1 tag.

Steps:

1. Run full local pytest suite.
2. Run release preflight.
3. Generate one complete release bundle from the infrastructure lane.
4. Generate one complete release bundle from the authorization lane.
5. Run evidence invariant checks over all generated bundles.
6. Generate evidence-quality reports for all generated bundles.
7. Verify manifests and attestation envelopes.
8. Finalize release notes.
9. Confirm GitHub CI or document explicitly that v0.1 is local-runner-first.
10. Tag v0.1 only after the above pass.

Exit criteria:

- v0.1 release notes match repository reality;
- all local release checks pass;
- release artifacts are reproducible and hash-addressed;
- limitations are explicit.

## Strategic path to the full vision

The full vision is not merely a tool that writes JSON evidence. The target system is a verification kernel for AI-agent engineering workflows: every high-risk change should be converted into explicit verification intent, routed to an appropriate backend, checked against formal or policy obligations, normalized into auditable evidence, and enforced through CI or review gates.

To reach that vision, the work should proceed in this order:

1. finish evidence-quality integration;
2. unify release bundles;
3. consolidate command surfaces;
4. harden GitHub Action usage;
5. deepen formal backend substance;
6. expand benchmark coverage;
7. stabilize schemas;
8. cut v0.1;
9. then move toward multi-repository and multi-backend assurance.

The immediate next sprint should be Sprint 7B, not Sprint 8. Evidence-quality integration should be completed before building a larger release-bundle surface, because the release-bundle design should include quality reports and invariant checks from the start.

## Release readiness judgment

Current state: v0.1 candidate, not v0.1 release-ready.

The repository is strong enough to present as an advanced prototype with credible release-hardening work. It is not yet strong enough to claim production-grade GitHub enforcement or complete formal verification. The best honest positioning is:

OVK is a local-runner-first verification kernel prototype with working evidence lanes, release artifacts, preflight checks, and evidence-quality gates. The next milestone is a v0.1 local release with explicit limitations, followed by GitHub Action hardening and deeper backend integration.
