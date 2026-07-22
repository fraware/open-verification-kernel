# OVK Vision Audit — 2026-07-22

## Executive judgment

Open Verification Kernel has achieved a credible **verification evidence product** for a bounded set of high-risk pull-request changes. It can infer five core checks from diffs, compile normalized lane inputs, execute deterministic or selected native checkers, aggregate evidence, produce conservative merge recommendations, render review output, and write hash-bound release bundles.

OVK has **not yet achieved the complete solver-agnostic verification-kernel vision** described by its architecture. The central missing capability is an enforced backend control plane. The kernel ranks backends and records routing decisions, but core obligations still execute a hard-coded lane evaluator. The selected backend does not determine compilation or execution. Most of the 100 template files are therefore catalog and routing assets, not executable end-to-end verification properties.

Current release judgment: **advanced v1.2.0 release candidate**. Advisory pilots are appropriate after the current branch passes CI. Production-stable, strict-by-default, or broad formal-verification claims are premature until backend routing is enforced, a tagged Action and wheel are exercised in an independent repository, and the current commit has an observed green release gate.

## Audit basis

This audit covers the current `main` branch after the latest engineer pushes and the corrective commits made during this review. It examines:

- kernel planning, routing, obligation compilation, execution, caching, and decision logic;
- all five core check lanes;
- OPA, Z3, CBMC, Cedar, TLA+, Kani, Dafny, Verus, Lean, and Alloy adapter surfaces;
- evidence, quality, Markdown, generated regression artifacts, attestations, manifests, envelopes, and provenance;
- CLI, MCP, composite GitHub Action, CI, publish workflow, wheel package data, benchmark, pilots, and documentation;
- fail-closed behavior at policy, manifest, cache, path, signing, and release boundaries.

The audit was performed through the GitHub repository API. Local cloning and test execution were unavailable in the audit environment. The latest observed HEAD is a benchmark badge commit marked `[skip ci]`, and it has no attached combined status entries. All modified code therefore requires a fresh CI run before release conclusions are final.

## Vision capability matrix

| Capability | Status | Assessment |
|---|---|---|
| Diff and changed-file ingestion | Substantially achieved | CLI and Action accept explicit inputs; the Action now materializes a PR diff automatically when no path is supplied |
| Change-surface detection | Achieved for bounded surfaces | CI/CD, authorization, infrastructure, secrets, and deployment surfaces are detected with conservative heuristics |
| Intent inference | Partially achieved | Five production lanes are inferred; most catalog templates are not connected to executable compilers |
| Risk ranking | Achieved as advisory metadata | Candidate intents receive deterministic risk scores; the scoring model is simple and not empirically calibrated |
| Backend capability discovery | Achieved | Packaged capability manifests are available to CLI, kernel, wheel, and MCP |
| Backend routing | Computed, not enforced | `selected` and `rejected` backends are recorded, but lane dispatch ignores the selected backend |
| Obligation compilation | Achieved for five lanes | Compilers produce normalized lane inputs from metadata and selected diff patterns |
| Native formal execution | Partial | OPA and Z3 have real native paths; CBMC checks bounded explicit or template harnesses; other adapters remain deterministic contracts or probes |
| Evidence normalization | Achieved | All lanes emit a common Pydantic evidence model with claims, assumptions, limits, counterexamples, and decisions |
| Conservative merge decision | Achieved | Fail blocks; unknown/error/skipped require review or configured fail-closed behavior |
| Evidence self-checking | Achieved and enforced | Invariant reports are generated; a quality report with `passed: false` now invalidates release output |
| Content-addressed bundle identity | Achieved with current fixes | Bundle IDs are derived from subject and ordered evidence; evidence IDs are obligation-scoped |
| Result caching | Achieved with current fixes | Cache keys now bind repository, commit, policy, OVK version, and relevant backend environment |
| Release bundle integrity | Substantially achieved | Required artifacts, schemas, manifest hashes, statement binding, envelope binding, HMAC, and identity-bound Sigstore verification are supported |
| Package portability | Substantially achieved | Runtime resources now resolve from packaged data; CI now includes a wheel smoke outside the checkout |
| GitHub Action consumer path | Substantially achieved | Default Action path now collects the real PR diff and quotes input arguments; an independent repository remains untested |
| MCP parity | Substantially achieved | MCP exposes packaged capabilities, planning, compilation, verification, bundles, decisions, and repair artifacts |
| Benchmark regression coverage | Strong internal coverage | FormalPR-Bench exercises curated lanes and diffs; it is not an independent external accuracy estimate |
| External validation | Not achieved | Current “external validation” is in-repository `uses: ./` dogfooding, not a tagged consumer repository |
| Production release evidence | Not achieved on current HEAD | The observed HEAD is `[skip ci]`; no current combined status was available during the audit |

## Architecture findings

### A. The evidence kernel is real

The repository now has a coherent internal sequence:

1. parse changed files or a unified diff;
2. detect engineering surfaces;
3. infer candidate intents;
4. rank intents;
5. compute backend routing candidates;
6. compile lane obligations;
7. execute obligations in deterministic submission order;
8. normalize evidence;
9. construct a content-addressed bundle;
10. derive a conservative merge decision;
11. produce review and release artifacts.

This is a meaningful architecture, not a collection of unrelated scripts. Subject consistency, duplicate evidence IDs, deterministic ordering, cache binding, and quality invariants now receive explicit enforcement.

### B. Routing remains descriptive

`route_intent` produces selected and rejected capability candidates, but `execute_obligations` dispatches through `evaluate_lane(lane, ...)`. The selected backend is attached to evidence as routing metadata with `routing_enforced: false`.

Consequences:

- changing routing scores does not change the checker that runs;
- backend budgets and allow/deny lists affect the plan but not core lane execution;
- a template may appear routable without having an executable backend compiler;
- the product is solver-aware, but the kernel is not yet solver-controlled.

This is the primary remaining gap between the implemented system and the stated vision.

### C. Template breadth exceeds executable breadth

The package includes approximately 100 intent templates, but executable end-to-end support is concentrated in five core lanes and a small set of backend fixture intents. A template is not operational merely because:

- it validates against the intent schema;
- a capability manifest claims domain/property support;
- the router returns a selected backend.

An operational template requires a compiler, material acquisition path, selected-backend execution, evidence semantics, counterexample translation, regression coverage, and fail-closed unknown behavior. The repository needs a generated conformance matrix proving those links for every advertised executable template.

## Lane-by-lane assessment

### Self-protection

Strengths:

- detects attempts by an AI agent to weaken its own workflow, required checks, verification files, or CODEOWNERS protections;
- treats missing high-risk metadata as unknown/review instead of pass;
- supports deterministic and optional OPA strategies;
- integrates GitHub event and branch-protection metadata.

Remaining limitations:

- auto-collected branch metadata cannot reconstruct removed required checks because it generally observes only current branch protection;
- reliable strict enforcement therefore requires trusted before/after metadata or a base-branch collector;
- workflow semantics remain narrower than GitHub Actions’ full permission and reusable-workflow model.

### Authorization

Strengths:

- validated normalized route abstractions;
- deterministic counterexample path and optional native Z3 SMT execution;
- malformed inputs require review;
- concrete route witnesses become regression artifacts.

Remaining limitations:

- route extraction is regex- and line-oriented;
- `admin_only_before` is inferred from the post-image and naming patterns rather than reconstructed from the base revision;
- framework middleware composition, inherited guards, decorators, route groups, and dynamic authorization remain outside the model;
- a Z3 proof is only as strong as the extracted abstraction.

### Infrastructure exposure

Strengths:

- native normalized schema plus Terraform-style, Kubernetes-style, and graph normalization hooks;
- configurable blocked sensitivity policy;
- conservative invalid-input handling;
- generated regression artifacts;
- manifest policy files now participate in provenance and cache identity.

Remaining limitations:

- direct diff extraction uses best-effort regex and partial-hunk reconstruction;
- provider defaults, module expansion, computed values, IAM semantics, network reachability, and full Kubernetes admission behavior are not modeled;
- source-grounded strict enforcement should use Terraform plan JSON, provider-aware policy engines, or another canonical IR.

### CI secrets

Strengths:

- parses workflow YAML and changed workflow post-images;
- recognizes untrusted triggers, secret references, and the high-risk `pull_request_target` plus PR-head-checkout pattern;
- produces focused counterexamples and regression output.

Remaining limitations:

- GitHub expression evaluation, reusable workflows, composite actions, environment protections, secret inheritance, job conditions, event filters, and permissions inheritance are incomplete;
- serialized-marker detection can over- or under-approximate secret use;
- the trust context needs to be derived from the actual event and workflow relationship in all entry points.

### Deployment approval state

Strengths:

- models states, transitions, required approvals, and production reachability;
- blocks direct paths that skip required states;
- emits counterexamples and regression artifacts.

Remaining limitations:

- diff extraction relies on YAML indentation and marker heuristics;
- production semantics, environment reviewers, deployment jobs, rollback policy, progressive delivery, and external deployment controllers are not integrated;
- a production strict lane should compile from an explicit deployment-state schema or provider API.

## Backend execution assessment

### OPA

OPA has a real `opa eval` execution path. Missing binaries and timeouts do not fabricate pass results. The generic kernel still needs to enforce router selection before OPA can serve as a dynamically selected backend for arbitrary compatible intents.

### Z3

Z3 has genuine native SMT execution over the normalized authorization obligation. Its guarantee is bounded by the abstraction, witness completeness, and query polarity. It is the strongest current example of a native semantic backend.

### CBMC

CBMC now distinguishes three cases:

- explicit caller-supplied harness: bounded model checking of that program model;
- OVK fixture/generated template harness: native model checking of a reusable risk model;
- binary-unavailable fallback: deterministic classification of supplied findings.

Native timeout or execution error now returns unknown/error and requires review. Template-harness evidence explicitly states that the changed project source was not compiled into the checked model. Full project verification still requires source selection, compilation flags, environment models, harness generation tied to changed functions, and source-to-property traceability.

### Cedar

Cedar currently performs deterministic evaluation of a Cedar-shaped input and separately probes the CLI version. Binary presence is no longer represented as native policy execution. Native Cedar authorization evaluation remains unimplemented.

### TLA+, Kani, Dafny, Verus, Lean, and Alloy

These adapters provide capability metadata, deterministic fixture contracts, normalized evidence, and integration scaffolding. They do not currently execute the native proof/model checker. They should remain informational until their compilers and native runners are implemented and tested.

## Artifact-by-artifact assessment

### `ovk-evidence.json`

Status: strong core artifact.

It contains subject identity, change origin, intent, backend claims, assumptions, limits, counterexamples, generated artifacts, and lane decisions. Current fixes reject subject-mismatched bundles and duplicate evidence IDs, and kernel/manifest evidence IDs are scoped to compiled obligations.

Remaining work:

- add explicit obligation ID and compiler version fields to the canonical model;
- record requested, selected, and executed backend separately in typed fields rather than only generated artifacts;
- add material digests as typed claim inputs;
- define confidence/coverage semantics for inferred abstractions.

### `ovk-evidence-quality.json`

Status: enforced internal-consistency artifact.

The quality report checks contradictory decisions, missing claim metadata, subject mismatch, duplicate IDs, native-execution honesty, and content-addressed bundle IDs. Release validation now rejects a schema-valid report whose `passed` value is false.

Remaining work:

- distinguish invariant errors from coverage warnings in release policy;
- add cross-artifact checks between evidence input digests, provenance materials, and obligation records;
- add routing consistency once backend selection becomes authoritative.

### `ovk-pr-comment.md`

Status: useful human-review artifact.

It communicates the merge recommendation and evidence in reviewer-facing form. It should remain a view over machine-readable evidence, never an independent source of truth.

Remaining work:

- render abstraction coverage and material provenance prominently;
- distinguish native, deterministic, template-model, skipped, and unknown results visually;
- include stable links to generated regression artifacts and source locations.

### `ovk-attestation.json`

Status: strong statement-binding primitive.

The statement binds bundle identity and digest. The release verifier checks the statement against the evidence bundle.

Remaining work:

- use a standard in-toto/SLSA predicate or publish a precise mapping;
- include the obligation compiler and backend toolchain identity;
- include policy/config digests in the attested predicate.

### `ovk-artifact-manifest.json`

Status: strong hash inventory.

The manifest records artifact paths, SHA-256 digests, sizes, and kinds. Verification now rejects absolute and parent-traversal paths outside the bundle root.

Remaining work:

- include the envelope or define explicitly why the envelope is outside its own manifest to avoid recursive hashing;
- define canonical path normalization across platforms;
- optionally include media type and schema version per artifact.

### `ovk-attestation-envelope.json`

Status: substantially hardened.

It binds the attestation statement to the artifact-manifest digest, supports HMAC, and supports Sigstore/cosign bundles. Explicit Sigstore signing fails closed. Sigstore verification is bound to an expected certificate identity and OIDC issuer.

Remaining work:

- exercise keyless signing and verification in a protected release workflow;
- publish the exact trusted identity/issuer policy;
- clarify HMAC key distribution and verification behavior for offline consumers;
- add timestamp/transparency-log policy if required by the threat model.

### `ovk-provenance.json`

Status: useful provenance foundation.

It records builder version, evidence-bundle digest, materials, invocation environment, and VCS data. Material URIs no longer expose absolute local paths.

Remaining work:

- record backend binary/container digests and compiler versions;
- record base/head source materials and the exact diff digest;
- capture trusted workflow identity and runner image;
- define redaction policy for sensitive material names.

### Generated regression artifacts

Status: useful repair-loop interface.

Several lanes turn concrete counterexamples into test artifacts. This supports agent repair and reviewer reproducibility.

Remaining work:

- validate generated code before writing it into a repository;
- use language/framework-aware generators;
- bind each generated test to evidence and source locations;
- avoid treating generated tests as proofs of the original property.

### FormalPR-Bench and leaderboard artifacts

Status: strong internal regression corpus, limited external validity.

The benchmark covers pass/fail/unknown behavior, routing, repair hints, realistic diffs, and several adversarial evidence cases. Its 130/130 result means the implementation matches its curated expectations.

It does not establish a 100% real-world detection rate because:

- cases and expectations are maintained in the same repository;
- extraction heuristics and labels are not independently adjudicated;
- some metrics test declared routing/evidence fields rather than independent backend execution;
- the realistic diff corpus remains small and synthetic or curated.

Required next benchmark phase:

- frozen holdout corpus from external repositories;
- independent double annotation;
- separate precision, recall, unknown rate, and abstention quality;
- per-surface severity and false-positive costs;
- actual selected-backend execution checks;
- versioned benchmark governance preventing test-set tuning.

## Changes applied during this audit

The audit directly modified `main` to address clear correctness and trust defects:

1. Bound result-cache keys to repository, commit, policy digest, OVK version, and relevant backend environment.
2. Added subject-bound cache regression coverage.
3. Scoped evidence IDs to compiled obligations and manifest entries.
4. Rejected subject-mismatched and duplicate-ID bundles at construction.
5. Preserved deterministic execution ordering.
6. Resolved templates, schemas, examples, and capability manifests from wheel package data.
7. Added an installed-wheel smoke outside the checkout.
8. Aligned MCP capability discovery and verification with packaged resources while preserving release-metadata compatibility.
9. Fixed CBMC timeout/error fail-closed behavior.
10. Fixed the generated integer-overflow safe harness constraint.
11. Distinguished explicit, fixture, and generated CBMC harness provenance and guarantees.
12. Corrected Cedar evidence so a version probe is not labeled native policy execution.
13. Made malformed or schema-invalid verification policy configuration fail closed.
14. Made failed evidence-quality reports invalidate outputs.
15. Constrained release-manifest artifact paths to the bundle root.
16. Constrained verification-manifest inputs and policies to a bounded workspace and included policy files in provenance.
17. Tightened the verification-manifest schema and canonical lane vocabulary.
18. Made repository-memory routing priors disabled by default and based on conclusive execution, not pass frequency.
19. Prevented absolute local paths from leaking through provenance material URIs.
20. Added Sigstore envelope schema support, fail-closed signing, and identity/issuer-bound verification.
21. Reworked the composite Action to collect the real PR diff by default and quote all path inputs.
22. Added Action dogfood for automatic diff collection and job-scoped artifact names.
23. Bound publish workflow version to the GitHub release tag and expanded release gates.
24. Rewrote backend documentation to match actual execution semantics.

## Remaining engineering program

### P0 — Required before calling the kernel vision achieved

#### Work package 1: Enforced backend control plane

Objective: make router selection determine compilation and execution.

Required design:

- define a typed `BackendAdapter` protocol with `can_handle`, `compile`, `run`, `normalize`, and `explain`;
- compile an intent/change pair separately for every selected backend;
- record immutable requested, eligible, selected, attempted, and executed backend sets;
- execute selected backends under wall-time, memory, and concurrency budgets;
- define aggregation semantics for disagreement, unknown, timeout, and fallback;
- prohibit unselected fallback unless policy explicitly permits it;
- set `routing_enforced: true` only after these invariants hold;
- fail closed if no selected backend produces evidence.

Acceptance criteria:

- changing allowed/denied backends changes the executed checker;
- tests prove an unselected backend cannot affect a decision;
- tests prove timeout and disagreement aggregation;
- evidence and quality gates detect selected/executed mismatch;
- every executable template maps to at least one tested compiler/backend pair.

#### Work package 2: Executable template conformance matrix

Objective: separate catalog templates from production-executable templates.

Required artifact:

`docs/benchmarks/template-conformance.json` containing, for every template:

- schema validity;
- compiler identifier and version;
- supported material sources;
- eligible backends;
- native/fallback guarantee classes;
- pass, fail, malformed, and unknown fixtures;
- counterexample and repair-generator availability;
- CI test references;
- production support status.

Acceptance criterion: public docs derive executable counts from this generated artifact. No template is described as supported unless all required links pass CI.

#### Work package 3: Current-commit release evidence

Objective: establish a green, attributable release gate.

Required actions:

- run CI on a non-`[skip ci]` commit containing all audit fixes;
- publish workflow/job links in release status;
- preserve JUnit, benchmark, wheel-smoke, Action-smoke, and preflight artifacts;
- require branch protection on core CI, package, and native Tier 1 checks;
- prevent badge automation from obscuring the verified source commit.

Acceptance criterion: release status names an exact source SHA and exact successful workflow runs.

#### Work package 4: Independent tagged consumer validation

Objective: prove that the released Action and wheel work outside OVK.

Required setup:

- separate public fixture repository owned by a different workflow context;
- use `fraware/open-verification-kernel@<immutable SHA or release tag>`, never `uses: ./`;
- install the published wheel from PyPI or release artifact;
- exercise advisory allow, advisory block, strict block, unknown/review, comment, check run, manifest bundle, and fork-PR permission behavior;
- upload artifacts back to the OVK release evidence ledger.

Acceptance criterion: two independent repositories complete at least 30 advisory PRs each with adjudicated false-positive and missed-detection records.

### P1 — Required for credible strict production use

#### Source-grounded authorization compilation

- add framework-specific AST adapters for at least two supported stacks;
- load base and head revisions;
- model route groups, middleware order, decorators, inherited guards, and role predicates;
- emit source ranges and extraction confidence;
- require review when extraction completeness is insufficient.

#### Provider-grounded infrastructure compilation

- consume Terraform plan JSON as the principal Terraform input;
- add provider-aware public exposure and IAM rules;
- model Kubernetes Service, Ingress, Gateway, NetworkPolicy, RBAC, and admission-relevant fields;
- separate public reachability from sensitivity classification;
- preserve module/resource addresses and source references.

#### Full GitHub Actions trust analysis

- evaluate reusable workflows and composite actions;
- propagate `secrets: inherit`, environment secrets, permissions, event filters, and job conditions;
- model checkout refs and untrusted-code execution precisely;
- distinguish secret availability from secret reference text;
- test against a corpus of real workflow incidents.

#### Deployment-system adapters

- compile from explicit deployment-policy schemas and selected providers;
- model environment protection, reviewer requirements, rollout gates, rollback, and promotion chains;
- expose a canonical deployment state-machine IR.

#### Project-grounded CBMC

- map changed C/C++ functions to harnesses and assertions;
- compile project source, headers, defines, and environment models;
- include exact command, unwind, architecture, and source digest in evidence;
- treat template harnesses as calibration only.

#### Trusted policy and memory acquisition

- load policy and historical reliability from the protected base branch or signed store;
- prohibit PR-head modification of enforcement policy from affecting the same PR;
- version and attest router reliability data;
- keep pass/fail outcome frequency separate from checker reliability.

### P2 — Ecosystem and scale

- native Cedar, TLA+, Kani, Dafny, Verus, Lean, and Alloy execution;
- sandboxed backend workers with CPU, memory, network, and filesystem isolation;
- remote execution protocol and reproducible backend containers;
- in-toto/SLSA-compatible provenance profile;
- SBOM and container/toolchain digests;
- organization policy service and reusable property registry;
- longitudinal external benchmark governance;
- calibrated risk ranking and abstention thresholds;
- signed evidence index for institutional audits.

## Release and adoption recommendation

### Suitable now, after a green current-commit CI run

- local development and demonstrations;
- advisory GitHub Action pilots;
- evidence-format and agent-repair integrations;
- internal evaluation of five bounded risk lanes;
- release-bundle and provenance experimentation.

### Suitable only after repository-specific calibration

- strict required checks for the five supported lanes;
- automated blocking where the abstraction source is trusted and complete;
- HMAC-signed internal release evidence with controlled key distribution.

### Not yet supported as a general claim

- formal verification of arbitrary pull requests;
- dynamic solver-agnostic backend enforcement;
- native execution across all ten advertised formal tools;
- production-stable accuracy across external repositories;
- 100% real-world detection or zero false positives;
- independent external validation of the tagged Action and published wheel.

## Questions for the engineering team

1. Is the intended product boundary five deeply supported lanes, or a general 100-template execution platform? The architecture and public claims should choose one near-term release contract.
2. Which exact backend-selection aggregation policy should govern disagreement: fail-dominant, quorum, strongest-guarantee, or policy-specific composition?
3. Which two application frameworks should receive the first source-grounded authorization compilers?
4. Which infrastructure IR is authoritative for strict mode: Terraform plan, OPA/Rego input, cloud-provider graph, or a new OVK IR?
5. Will the protected base branch or a remote service provide policy and historical reliability data?
6. What immutable GitHub identity and OIDC issuer should be trusted for Sigstore release signing?
7. Which independent repositories are available for tagged Action and wheel validation?
8. Should `Development Status :: 5 - Production/Stable` remain in package metadata before those pilots and routing enforcement are complete?

## Bottom line

The engineers have built a substantial system and addressed many prior audit findings. OVK now has a credible evidence contract, conservative decision layer, bounded verification lanes, packaging surface, GitHub integration, benchmark harness, and release-artifact chain.

The remaining work is concentrated and consequential. OVK becomes the envisioned solver-agnostic verification kernel only when backend routing controls execution, advertised templates are proven executable through a generated conformance matrix, extraction is grounded in authoritative source representations, and release claims are supported by current CI and independent tagged consumers.
