# Open Verification Kernel Deep Audit — Revision 2

**Date:** 2026-07-23  
**Repository:** `fraware/open-verification-kernel`  
**Scope:** current `main` after the latest engineer push and corrective changes made during this audit

## Executive judgment

The engineer push implemented the most important architectural transition in the OVK roadmap. The repository now contains a real typed backend control plane, backend-neutral obligations, typed routing decisions, registered adapters, backend-specific compilation, normalized execution attempts, fail-dominant aggregation, evidence v2, five enforceable lane paths, source-compiler profiles, template conformance generation, independent consumer repositories, holdout evaluation plumbing, and a materially stronger release-artifact chain.

The complete vision is still not achieved.

The system is best described as an **advanced, policy-selectable verification kernel release candidate**. Backend selection controls execution inside the new control plane when a lane is explicitly enforced. The default product path remains shadow/legacy-authoritative. The current branch also contains several P0 trust defects that must be fixed before a new release can claim reliable enforced routing:

1. cache hits do not preserve the original execution attempt and can fabricate native-execution provenance from current tool availability;
2. execution-attempt identifiers include nondeterministic duration data;
3. a compiler/backend guarantee mismatch is silently rewritten instead of rejected;
4. backend selection ignores `coverage_requirements_met`;
5. fallback acceptance is represented as a broad boolean and does not enforce the configured fallback backend set;
6. self-protection metadata is trusted by default unless repository policy explicitly disables trust;
7. in-process adapters receive only soft timeout checks and cannot be cancelled;
8. evidence v2 and its schema do not yet make the complete routing and execution trace mandatory or cryptographically cross-bound;
9. the release and consumer evidence currently validate tag `v1.2.1`, whose commit predates the new control-plane implementation.

The release judgment is therefore:

> **Current `main` is post-v1.2.1 development code and should be treated as a v1.3.0 release-candidate line. It is appropriate for internal testing and advisory pilots after current-source CI is green. It is not yet suitable for production-stable or broadly strict enforcement claims.**

## Audit basis and evidence provenance

The previous signed release is tag `v1.2.1` at commit:

`a27d5720f4350c00bca34f71d991c31f5a2f38c7`

GitHub Actions run `30010876652` successfully completed:

- release verification;
- the package build;
- isolated wheel smoke;
- keyless Sigstore signing and verification.

That run is valid evidence for the tagged `v1.2.1` source.

It is not evidence for the current control-plane branch. The current branch is more than eighty commits ahead of that tag and adds the control plane, enforced adapters, source compilers, evidence v2, template conformance, holdout runner, consumer infrastructure, and later audit fixes.

Two independent consumer repositories now exist:

- `fraware/ovk-consumer-fastapi-terraform`;
- `fraware/ovk-consumer-express-actions`.

They currently pin `fraware/open-verification-kernel@v1.2.1` and package version `1.2.1`. They are useful external-consumer scaffolds, but they do not validate the newly pushed control-plane source.

The current branch must receive new attributable CI, native-backend, wheel, Action, consumer, and release-bundle evidence before publication.

## Vision-achievement matrix

| Capability | Current status | Judgment |
|---|---|---|
| Typed verification subject and materials | Implemented | Strong foundation |
| Backend-neutral obligation | Implemented for five lanes | Strong foundation |
| Typed backend registry | Implemented | Strong |
| Typed routing decision | Implemented | Strong data model |
| Selected backend controls execution | Implemented inside enforced control-plane path | Genuine architectural achievement |
| Default product path | Shadow/legacy-authoritative | Migration state, not universal enforcement |
| One authoritative route from inference to evidence | Not implemented | Legacy route and typed route coexist |
| Backend-specific compilation | Implemented for registered production adapters | Strong but guarantee validation incomplete |
| Fail-dominant aggregation | Implemented | Strong high-level semantics; fallback details incomplete |
| Backend execution cache | Routing and environment bound | Provenance loss on cache hits is P0 |
| Hard execution budgets | Partial | Subprocess worker exists; in-process adapters are soft bounded |
| Evidence v2 | Implemented | Model and schema require strengthening |
| Evidence quality | Broad invariant set implemented | Several invariants validate presence, not canonical recomputation |
| Release artifacts | Strong hash, attestation, provenance, and signing foundation | Cross-artifact material binding remains absent |
| Five enforced lanes | Available by policy | Default remains shadow |
| Authorization source compiler | Implemented as regex profile | Advisory-grade, not general strict-grade |
| Terraform plan compiler | Implemented as limited profile | Advisory/profile-limited |
| Kubernetes compiler | Implemented as limited profile | Advisory/profile-limited |
| GitHub Actions trust compiler | Implemented | Valuable advisory detector, incomplete semantics |
| Deployment compilers | Implemented for supplied abstractions | Bounded profile verification |
| Project-grounded CBMC | Scaffolding implemented | Full project compilation and harness traceability incomplete |
| Template catalog separation | Implemented | 95 catalog-only entries are honestly separated |
| Strict semantic conformance | Not implemented | Current gate primarily checks repository-link existence |
| Internal benchmark | Implemented | Regression signal, not independent accuracy |
| Holdout evaluation | Evaluator path implemented | Prediction generation and full isolation incomplete |
| Independent consumers | Repositories and pinned workflows exist | They validate the previous tag, not current source |
| Current-source release evidence | Not established | Required before next release |

# 1. Kernel and routing audit

## 1.1 What is now real

`BackendRegistry` validates adapter and backend identities, rejects duplicates, validates capability manifests, and provides deterministic capability assessment.

`BackendControlPlane.execute` iterates `RoutingDecision.selected`, retrieves only the named adapters, compiles backend-specific obligations, calculates environment fingerprints, executes adapters, normalizes results, records attempts, and aggregates the selected result set.

This means selection can genuinely alter which backend runs. Authorization tests select either:

- `authorization-deterministic`;
- `z3-native`.

Self-protection can select:

- `self-protection-deterministic`;
- `opa-native`.

Infrastructure, CI secrets, and deployment each have a deterministic registered adapter.

## 1.2 Dual routing remains

`execute_kernel` still computes compatibility routing from inferred intents and static capability manifests before obligations are compiled. `adapter_runtime` later compiles a typed obligation and computes a second typed route for shadow or enforced execution.

Consequences:

- `KernelResult.routing` can differ from the route that produced enforced evidence;
- CLI and MCP planning surfaces can report a backend set different from the authoritative execution set;
- policy normalization and scoring are duplicated;
- routing identity is not a single immutable object from inference through attestation.

Required resolution:

1. infer candidate intents;
2. compile typed neutral obligations;
3. route each obligation exactly once through `route_obligation`;
4. pass those immutable decisions to execution;
5. return the actual routing decisions in `KernelResult`;
6. deprecate `route_intent` for internal execution.

## 1.3 Coverage-blind selection

Capability assessments include:

- `material_requirements_met`;
- `coverage_requirements_met`.

The typed router filters material requirements, guarantee compatibility, support, budget, and allow/deny policy. It does not reject a candidate whose `coverage_requirements_met` value is false.

This allows a backend to become the required primary even when the adapter’s own capability assessment says the obligation lacks sufficient abstraction coverage.

The evidence converter later downgrades an `allow` when overall obligation coverage is incomplete, which reduces immediate safety risk. It does not repair the routing inconsistency or prevent an unsupported backend execution from being represented as selected primary.

Required behavior:

- `coverage_requirements_met == false` must make the candidate ineligible for required-primary selection;
- partial support may be optional corroboration only when repository policy permits it;
- the rejected reason must state the exact coverage failure;
- quality validation must reject a required selection that contradicts capability assessment.

## 1.4 Guarantee rewriting

After an adapter compiles a backend obligation, the control plane compares the compiled `expected_guarantee` with the routing selection’s expected guarantee. When they differ, the current code rewrites the backend obligation to the router’s value.

This is unsafe. The compiler is the component that knows which guarantee its generated payload can support. The router must select based on declared capability; it must not relabel a weaker or different compiled guarantee.

Required behavior:

- a mismatch produces an explicit `invalid_output` or `compiler_contract_error` attempt;
- no backend execution occurs for the mismatched obligation;
- the result requires human review;
- evidence-quality validation reports selected/compiled guarantee mismatch;
- tests include a malicious or defective adapter that returns a different guarantee.

## 1.5 Fallback semantics are too broad

Aggregation receives a single `fallback_accepted` boolean. When true, a required result whose guarantee is outside the obligation’s acceptable guarantee set can be accepted.

The configured `FallbackPolicy.fallback_backends` and per-backend guarantee downgrade are not enforced by aggregation.

Required behavior:

- fallback acceptance must be evaluated per backend and guarantee;
- fallback is valid only when the selected backend is in the configured fallback set;
- the fallback guarantee must appear in an explicit accepted-fallback guarantee set;
- a native attempt that timed out or errored cannot be replaced by fallback in the same execution unless policy explicitly defines a second independent required attempt;
- evidence records the downgrade and why it was accepted.

# 2. Execution identity and cache audit

## 2.1 Attempt identifiers are nondeterministic

`attempt_digest_input` excludes `started_at` and `finished_at`. It still includes `duration_ms`.

Execution duration varies across equivalent runs. As a result:

- equivalent execution attempts can receive different attempt IDs;
- evidence that embeds attempts can differ across runs;
- bundle and attestation digests can change even when inputs, tools, outputs, and decisions are identical.

Required resolution:

- remove `duration_ms` from the attempt identity;
- define attempt identity from backend obligation, backend, termination, native flag, tool identity, exit code, raw output digests, and worker image/tool digest;
- keep timing as observational metadata outside identity;
- add a test proving different timestamps and durations yield the same attempt ID;
- add a test proving changed termination, exit code, raw result, or tool digest changes the ID.

## 2.2 Cache hits lose execution provenance

The hardened cache stores `NormalizedBackendResult`, with metadata stored beside it. The control-plane cache interface returns only the normalized result.

On a cache hit, the control plane creates a new `ExecutionAttempt` and sets `native_execution` from the current environment fingerprint’s `native_available` field.

Tool availability is not proof that the cached result originally came from native execution.

Consequences:

- deterministic cached results can be represented as native if the tool is now installed;
- native cached results can lose original tool version, exit code, timing, worker image, and termination provenance;
- quality checks can be satisfied by reconstructed current-state metadata instead of the original attempt.

Required resolution:

- cache a typed `CachedBackendExecution` containing the normalized result, original execution attempt, raw-result digest, environment fingerprint, adapter identity, and cache creation metadata;
- return that complete object on cache hit;
- preserve original `native_execution`, tool version, tool digest, exit code, termination, and attempt ID;
- add `cache_hit: true` as separate observational metadata;
- never synthesize original provenance from the current environment;
- invalidate all old backend-result cache entries by incrementing the cache schema version.

## 2.3 In-process adapters are not hard bounded

Several deterministic adapters run inside the OVK Python process. They compare elapsed time with the budget after the evaluator returns.

A hung evaluator cannot be interrupted by that check.

Required resolution:

- run every authoritative adapter behind a worker boundary;
- use subprocess or spawned-process workers for deterministic adapters;
- enforce wall time outside adapter code;
- enforce memory and output limits;
- provide a minimal environment;
- prohibit repository writes unless policy permits them;
- record worker identity and termination reason.

## 2.4 Worker environment defect fixed during this audit

The worker described itself as an environment allowlist but inherited every parent variable except a finite denylist. Unknown credentials could therefore reach native tools.

This audit changed the worker so:

- only configured parent keys are inherited;
- explicit non-secret variables may be added by the caller;
- known credential keys remain forbidden;
- a non-positive timeout returns an immediate timeout without execution.

New tests cover unknown parent credentials, explicit safe variables, and zero-budget execution.

# 3. Self-protection trust audit

The compiler supports trusted and untrusted before/after branch-protection materials. Enforced runtime currently defaults `metadata_trusted` to true unless repository policy explicitly sets it false.

This is the wrong trust default.

Metadata may originate from:

- a PR-controlled file;
- current branch-protection collection that cannot reconstruct the removed base state;
- synthetic examples;
- an explicitly trusted base-branch collector.

Required resolution:

- default `metadata_trusted` to false;
- require a provenance object identifying collector, repository, revision, API endpoint or material source, collection time, and digest;
- only a protected base-branch workflow, signed external service, or explicit maintainer-supplied material may set trust true;
- current-state-only branch protection cannot authorize `allow` for gate preservation;
- untrusted complete-looking metadata must remain review-only;
- add adversarial tests where PR-head metadata falsely reports an unchanged gate.

# 4. Evidence and artifact audit

## 4.1 Evidence v2 is useful but not fully mandatory

The Pydantic model adds typed control-plane fields, but many are optional. The JSON schema requires only a subset and allows broad additional properties.

The schema does not require the complete trace:

- compiler identity;
- materials;
- coverage;
- requested and eligible backends;
- attempted backends;
- execution attempts;
- routing-enforced state.

Required resolution:

- create evidence schema v2.1 or v3;
- require all control-plane fields for `routing_enforced: true` evidence;
- reference material, coverage, routing, and execution schemas instead of open objects;
- make selected backend entries typed so required and optional roles are preserved;
- make execution attempt linkage explicit through obligation and routing IDs.

## 4.2 Invariants validate presence more often than canonical truth

Examples:

- routing ID is checked for presence but is not recomputed from embedded routing content;
- aggregate decision is not recomputed from typed selected roles and results;
- material digests are checked for shape/presence but not cross-verified against provenance and attestation;
- attempt-to-obligation linkage is weak because attempts do not carry obligation ID;
- selected backend names lose required/optional role information in evidence.

Required resolution:

- embed the typed routing decision or a canonical signed digest plus selected-role records;
- recompute routing ID during validation;
- recompute aggregate outcome from results and selected roles;
- add obligation ID and routing ID to attempts;
- verify material-set equality across obligation, evidence, provenance, and attestation.

## 4.3 Cross-artifact material binding remains absent

Define one canonical `material_set_digest` over sorted material references.

Place it in:

- `VerificationObligation`;
- `VerificationEvidence`;
- provenance predicate;
- attestation statement;
- attestation envelope or manifest metadata.

Release verification must recompute and compare all values.

## 4.4 CI-secrets material-size defect fixed during this audit

The legacy CI-secrets compiler still used the digest string length as `size_bytes`.

This audit migrated it to `material_reference_from_payload` and added a regression test binding size to canonical serialized bytes.

# 5. Source compiler audit

## 5.1 Authorization

FastAPI and Express compilers create useful base/head IRs and source spans. They remain regex compilers.

FastAPI risks include:

- route decorator parsing stops at nested closing parentheses;
- dependency parsing can miss nested or multiline `Depends` expressions;
- included router and router prefix composition is incomplete;
- router identities are not module-qualified;
- duplicate route keys overwrite earlier entries;
- function analysis examines a bounded source suffix;
- absence of a detected unsupported pattern is treated as evidence of completeness.

Express risks include:

- middleware arguments are comma-split instead of AST parsed;
- nested calls and arrays are not modeled;
- import aliases and re-exports are incomplete;
- router prefix and mount resolution are file-local and name-based;
- duplicate route keys overwrite earlier entries;
- dynamic registrations can be missed.

Judgment:

> Both are source-referenced advisory profiles. They are not general strict-grade framework compilers.

Required next implementation:

- Python AST plus import/module graph for FastAPI;
- TypeScript compiler API or ESTree parser plus module graph for Express;
- route completeness accounting;
- explicit unresolved constructs;
- source-profile versioning;
- strict eligibility only for supported syntax subsets with independent corpus results.

## 5.2 Infrastructure

Terraform uses plan-shaped JSON, which is the correct strict-source boundary. Its present semantics are limited to top-level resource changes and a few generic exposure fields.

Missing semantics include:

- recursive child modules;
- `after_unknown` and sensitive values;
- provider defaults;
- resource dependencies;
- IAM policy effects;
- network routes and security groups;
- load balancer/listener relationships;
- provider-specific public exposure rules.

Kubernetes recognizes important object kinds, but currently:

- every Ingress is treated as public;
- LoadBalancer and NodePort are treated as public without controller or address context;
- Gateway listener/class semantics are incomplete;
- NetworkPolicy and RBAC are stored but do not constrain reachability;
- selectors, namespaces, Services, Endpoints, Routes, and policy intersections are not fully resolved.

Judgment:

> Useful advisory normalized profiles. Strict eligibility must be profile-specific and provider/controller-aware.

## 5.3 GitHub Actions

The compiler introduces the right trust-flow property, but currently treats every untrusted-trigger job or step as untrusted code. This is conservative and can create broad false positives.

Missing semantics include:

- event-specific secret availability;
- job-level permissions overriding workflow permissions;
- reusable workflow input, permission, and secret propagation;
- `secrets: inherit` flow;
- environment protection configuration;
- semantic evaluation of `if:` conditions;
- checkout repository and ref trust;
- remote actions and workflows;
- expression data-flow and sanitization.

Judgment:

> Strong advisory trust detector, not a complete GitHub Actions authorization semantics engine.

## 5.4 Deployment and CBMC

Deployment compilers are bounded interpreters over supplied schemas and selected provider objects. They do not yet prove external controller state, artifact identity, reviewer decisions, rollback viability, or rollout metrics.

CBMC has honest harness distinctions, but full project verification still requires source closure, compile database fidelity, changed-function mapping, generated environment models, unwind sufficiency, actual project compilation, and source-linked counterexamples.

# 6. Template conformance audit

The conformance matrix correctly separates 95 catalog-only templates from five linked production lanes.

Its `strict_eligible` status is still too strong. The gate checks existence of:

- intent file;
- evaluator;
- compiler;
- registry;
- pass example;
- fail example;
- enforcement test.

It does not establish:

- malformed and unknown behavior;
- compiler coverage completeness;
- source-material acquisition;
- selected/executed backend consistency;
- native versus deterministic guarantee strength;
- counterexample correctness;
- artifact integrity;
- external calibration.

Required status model:

- `catalog_only`;
- `executable_advisory`;
- `source_profile_strict_eligible`;
- `externally_calibrated_strict`;
- `deprecated`.

No template should be `source_profile_strict_eligible` unless its source compiler’s supported subset, coverage requirements, negative corpus, unknown corpus, and artifact checks are generated and tested.

# 7. Holdout and external validation audit

## 7.1 Holdout runner defects fixed during this audit

The downloaded holdout artifact contained an executable `harness/evaluate.py`.

Before this audit:

- remote assets were not checked against an independent digest;
- Python 3.10/3.11 fell back to unrestricted `tar.extractall`;
- archive links and special files were not rejected;
- the downloaded evaluator inherited `HOLDOUT_DOWNLOAD_TOKEN` and runner environment;
- aggregate output was not fully validated against the JSON schema;
- `leakage_guard.fail_closed` was not required to be true.

This audit changed the runner and workflow to require:

- an independently supplied SHA-256 for remote assets;
- path-safe manual extraction;
- rejection of links, devices, FIFOs, and special members;
- isolated Python execution with a minimal environment and no tokens;
- full Draft 2020-12 schema validation;
- strict leakage guard enforcement;
- new supply-chain security tests.

Remaining holdout work:

- separate prediction and evaluation jobs;
- generate predictions from the exact current wheel/commit without labels;
- digest or sign predictions;
- record wheel, source, holdout asset, prediction, and aggregate digests;
- use a sandbox/container with network disabled for evaluator execution;
- publish only aggregate metrics.

## 7.2 Independent consumers exist but validate the old release

The two consumer repositories are real and contain:

- immutable Action pins;
- scenario matrices;
- advisory and strict workflow definitions;
- pilot ledgers;
- wheel-install scripts;
- fork simulations.

They currently pin `v1.2.1` at commit `a27d572...`.

The control-plane implementation is post-tag development. Therefore:

- consumer existence is established;
- current control-plane validation is not established;
- automated scenario entries are not human-adjudicated pilots;
- cross-fork and comment/check-run behavior still require attributable workflow evidence.

Required next step:

1. publish or pin an immutable current-source release candidate;
2. update both consumers;
3. dispatch every scenario workflow;
4. retain artifacts and run conclusions;
5. ingest results into the pilot ledger;
6. complete human adjudication targets before production claims.

# 8. Release and CI assessment

The green `v1.2.1` release run is valid for the old tag only.

Current `main` must pass:

- full unit and integration tests;
- lint;
- all release-preflight checks;
- template conformance;
- wheel-outside-checkout smoke;
- Action automatic-diff dogfood;
- strict-block Action dogfood;
- native OPA, Z3, and CBMC jobs;
- Cedar honesty probe;
- release-bundle adversarial checks;
- holdout security tests;
- consumer release-candidate scenarios.

Badge artifacts currently call the benchmark source SHA `verified_source_sha`. The badge workflow can produce that field after a benchmark-only workflow even when general CI is absent. Rename or split this provenance:

- `benchmark_source_sha` means the source evaluated by FormalPR-Bench;
- `verified_source_sha` is present only when an exact successful required workflow set is recorded;
- include workflow run IDs and conclusions in release status.

# 9. Direct changes made during this audit

1. Fixed CI-secrets material byte-size integrity.
2. Added CI-secrets material-size regression coverage.
3. Changed backend subprocess workers from denylist inheritance to a minimal parent-environment allowlist.
4. Added worker tests for unknown credential isolation, explicit safe variables, and non-positive timeout behavior.
5. Required immutable SHA-256 verification for remote holdout assets.
6. Replaced unsafe tar extraction with path-safe extraction and special-file rejection.
7. Removed tokens and inherited credentials from downloaded holdout evaluator execution.
8. Added full holdout aggregate schema validation and stricter leakage guards.
9. Updated the holdout workflow to install runner dependencies, require the asset digest, and validate the sanitized aggregate.
10. Added holdout path traversal, symlink, token isolation, digest, and leakage tests.

All changes require a fresh CI run on the current source.

# 10. Updated release verdict

## Suitable after current-source CI is green

- local development;
- internal evaluation;
- shadow-mode deployment;
- advisory pilots for the five bounded lanes;
- evidence and artifact integrations;
- controlled lane-specific enforced experiments.

## Suitable only after repository-specific calibration

- lane-specific strict required checks where:
  - material acquisition is trusted;
  - the compiler profile is explicitly supported;
  - coverage is sufficient;
  - the enforced backend has calibrated behavior;
  - fallback is disabled or explicitly bounded.

## Not yet supportable as a general claim

- production-stable enforcement for arbitrary repositories;
- complete formal verification of arbitrary pull requests;
- strict-grade FastAPI or Express coverage outside a documented supported subset;
- provider-complete Terraform or Kubernetes reachability;
- complete GitHub Actions trust semantics;
- native execution across all ten advertised tools;
- external accuracy derived from FormalPR-Bench;
- current-control-plane validation from the `v1.2.1` tag or its consumers.

# 11. Bottom line

The engineers achieved the architectural core that was previously missing: selected registered backends can now control execution inside the enforced control plane. The remaining work is no longer primarily about adding architectural nouns. It is about making the control plane trustworthy under cache reuse, compiler disagreement, incomplete coverage, fallback, untrusted metadata, execution budgets, cross-artifact verification, source semantics, and release provenance.

The next release must not reuse the `v1.2.1` evidence story. The new architecture requires a new attributable release-candidate cycle, updated consumer pins, current-source CI, native backend evidence, signed release artifacts, and end-to-end holdout and pilot results.
