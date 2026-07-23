# Open Verification Kernel Engineering Program — Revision 2

**Purpose:** standalone implementation instructions for completing the OVK vision after the latest control-plane push  
**Repository:** `fraware/open-verification-kernel`  
**Companion audit:** `docs/DEEP_AUDIT_2026-07-23_R2.md`

# 1. Program mandate

The next engineering phase must convert the current post-v1.2.1 control-plane branch into a release-substantiated, internally consistent, externally validated verification kernel.

The architecture already contains the right major components:

- backend-neutral obligations;
- typed capability assessments;
- typed routing decisions;
- backend-specific compilation;
- registered adapters;
- controlled execution records;
- normalized evidence;
- conservative aggregation;
- evidence-quality validation;
- release manifests, attestations, provenance, and signatures.

The remaining work must establish that these components preserve trust under:

- cache reuse;
- nondeterministic timing;
- incomplete abstraction coverage;
- compiler/backend disagreement;
- backend failure and fallback;
- untrusted metadata;
- resource exhaustion;
- malicious artifacts;
- source-compiler incompleteness;
- independent consumer use;
- release publication.

Do not add more adapter names or catalog templates until the P0 control-plane and release invariants below are complete.

# 2. Product and release boundary

## 2.1 Version boundary

Treat current `main` as the development line for:

`v1.3.0-rc.1`

Do not describe the current branch as the already released `v1.2.1` implementation.

`v1.2.1` at commit `a27d5720f4350c00bca34f71d991c31f5a2f38c7` remains the previous signed release. The typed control-plane implementation was added afterward.

## 2.2 Supported production profiles

The next release candidate may advertise five bounded profiles:

- self-protection;
- authorization;
- infrastructure exposure;
- CI secret exposure;
- deployment approval state.

The release candidate must distinguish:

- legacy-authoritative execution;
- shadow control-plane execution;
- lane-specific enforced execution;
- source-profile strict eligibility;
- externally calibrated strict eligibility.

## 2.3 Claims prohibited until later gates

Do not claim:

- production-stable enforcement across arbitrary repositories;
- complete formal verification of arbitrary changes;
- strict-grade support for all FastAPI, Express, Terraform, Kubernetes, GitHub Actions, or deployment semantics;
- native execution for Cedar, TLA+, Kani, Dafny, Verus, Lean, or Alloy;
- external accuracy from FormalPR-Bench;
- current-control-plane validation from the `v1.2.1` release or consumer pins.

# 3. Program invariants

Every pull request must preserve these invariants.

## 3.1 Selection integrity

A backend can affect a decision only when it was:

1. registered;
2. capability-assessed;
3. eligible;
4. selected;
5. compiled successfully;
6. attempted;
7. normalized successfully;
8. accepted by evidence-quality validation.

An unselected backend must never affect the decision.

## 3.2 Coverage integrity

A backend whose assessment has `coverage_requirements_met == false` cannot be a required primary backend.

A source compiler cannot produce strict `allow` unless:

- its supported source profile is identified;
- required source materials are complete;
- unsupported constructs are absent or explicitly accepted by policy;
- coverage status is complete;
- the minimum profile confidence threshold is satisfied.

## 3.3 Guarantee integrity

The adapter compiler determines the guarantee supported by its backend obligation.

The router cannot relabel that guarantee.

When routing and compilation disagree:

- do not execute the backend;
- emit `compiler_contract_error` or `invalid_output`;
- require human review;
- preserve the disagreement as a quality issue.

## 3.4 Cache provenance integrity

A cache hit must preserve the original:

- execution attempt;
- native-execution state;
- tool version and digest;
- termination;
- exit code;
- raw-result digest;
- worker identity;
- normalized result.

Current tool availability cannot be used to reconstruct prior execution provenance.

## 3.5 Fallback integrity

Fallback is valid only when:

- the backend is explicitly listed in `fallback_backends`;
- the fallback guarantee is explicitly accepted;
- the required backend was unavailable before execution or policy explicitly permits an independent fallback attempt;
- a native timeout, crash, invalid output, or resource exhaustion is not silently replaced by a passing fallback result.

## 3.6 Material integrity

One canonical material set must bind:

- obligation;
- evidence;
- provenance;
- attestation;
- release verification.

## 3.7 Release provenance integrity

A `verified_source_sha` exists only when the exact SHA has an observed successful required workflow set.

A benchmark-only run may record `benchmark_source_sha`. It must not create release-verification provenance.

# 4. Workstream ownership

Assign clear owners for four workstreams.

## Workstream A — Kernel correctness

Owns:

- execution models;
- router;
- registry;
- control plane;
- cache;
- aggregation;
- worker isolation;
- migration runtime.

## Workstream B — Evidence and supply chain

Owns:

- evidence schemas;
- invariants;
- rendering;
- provenance;
- attestation;
- release bundle;
- Sigstore;
- release workflows;
- verified source records.

## Workstream C — Semantic compilers

Owns:

- authorization profiles;
- Terraform and Kubernetes profiles;
- GitHub Actions trust semantics;
- deployment profiles;
- project-grounded CBMC;
- compiler coverage and corpus governance.

## Workstream D — External evaluation

Owns:

- template conformance;
- FormalPR-Bench governance;
- FormalPR-Holdout;
- consumer repositories;
- pilot ledgers;
- adjudication;
- release-candidate validation.

The execution and evidence contracts remain centrally reviewed. Compiler teams must not create local replacements for routing, attempt, result, or material models.

# 5. Sprint 0 — Establish the current-source baseline

## Objective

Produce attributable evidence for the current post-audit source before making additional architectural changes.

## Required actions

1. Select one non-badge source commit containing:
   - the latest engineer push;
   - CI-secrets material-size correction;
   - minimal worker environment correction;
   - holdout supply-chain corrections;
   - the Revision 2 audit and engineering program.
2. Disable or avoid benchmark badge commits while baseline workflows run.
3. Run:
   - general CI;
   - native Tier 1;
   - package/wheel smoke;
   - automatic-diff Action dogfood;
   - strict-block Action dogfood;
   - release preflight;
   - expanded FormalPR-Bench;
   - template conformance;
   - release-bundle adversarial tests.
4. Retain:
   - JUnit or test output;
   - benchmark summary;
   - wheel artifact;
   - Action evidence artifacts;
   - native backend artifacts;
   - release-preflight report.
5. Record exact source SHA and run IDs in `docs/CURRENT_RELEASE_STATUS.md`.

## Required corrections before the baseline can be called green

- update any test that assumes inherited worker environment;
- ensure `jsonschema` is installed for holdout runner tests;
- supply a holdout asset digest only in the optional holdout workflow;
- verify that Python isolated mode can execute the frozen holdout evaluator;
- resolve any package-data regression introduced by the current source.

## Acceptance criteria

- all required jobs are green on the same source SHA;
- no health statement cites a `[skip ci]` badge commit;
- generated benchmark files contain `benchmark_source_sha`;
- `verified_source_sha` is omitted until required workflows are verified.

# 6. Sprint 1 — Correct execution identity and cache provenance

## Objective

Make execution identity deterministic and cache reuse provenance-preserving.

## 6.1 Remove observational timing from attempt identity

### Files

- `ovk/core/execution_models.py`
- `tests/test_execution_models.py`
- `tests/test_adversarial_control_plane.py`

### Required changes

Change `attempt_digest_input` so it excludes:

- `attempt_id`;
- `started_at`;
- `finished_at`;
- `duration_ms`.

Retain identity-bearing fields:

- backend obligation ID;
- backend;
- required role;
- termination;
- native execution;
- tool version;
- tool digest;
- worker image digest;
- exit code;
- stdout digest;
- stderr digest;
- raw result digest.

### Tests

- different start, finish, and duration values produce identical attempt IDs;
- different termination changes the ID;
- different raw result changes the ID;
- different tool digest changes the ID;
- sequential and parallel equivalent executions produce the same bundle ID.

## 6.2 Cache the complete execution provenance

### Files

- `ovk/core/result_cache.py`
- `ovk/core/backend_control_plane.py`
- `ovk/core/execution_models.py`
- `tests/test_cache_worker_control_plane.py`
- `tests/test_verification_cache.py`

### New model

Add:

```python
class CachedBackendExecution(BaseModel):
    schema_version: Literal["ovk.cached_backend_execution.v1"]
    execution_attempt: ExecutionAttempt
    normalized_result: NormalizedBackendResult
    environment_fingerprint: BackendEnvironmentFingerprint
    raw_result_digest: str | None
    cached_at_unix_ms: int
```

### Required behavior

- store the complete object;
- return the complete object;
- reuse the original attempt ID and native flag;
- add `cache_hit: true` as separate metadata without altering original execution provenance;
- do not create a new completed native attempt on cache hit;
- increment `CACHE_SCHEMA_VERSION`;
- delete or ignore all previous backend-result cache entries.

### Required adversarial tests

1. Execute deterministic backend with native tool unavailable, cache it, install/mock tool availability, read cache, confirm `native_execution` remains false.
2. Execute native backend, cache it, remove/mock tool unavailable, read cache, confirm original native provenance and tool version remain intact.
3. Change tool digest and confirm cache miss.
4. Corrupt cached attempt and confirm cache miss or deletion.
5. Confirm cache hit does not change evidence or bundle identity.

## 6.3 Remove vacuous cache tests

Replace any assertion of the form:

```python
assert condition or True
```

with a direct identity assertion.

The policy-digest test must prove different policy digests produce different obligation IDs, routing IDs, or cache key components.

## Sprint 1 exit criteria

- attempt identity is deterministic;
- cache reuse preserves original execution provenance;
- no test can pass unconditionally;
- evidence and bundle identities are stable across cache misses and hits.

# 7. Sprint 2 — Enforce routing, coverage, guarantee, and fallback contracts

## Objective

Make the typed router and control plane reject inconsistent execution plans instead of repairing metadata silently.

## 7.1 Coverage-aware eligibility

### Files

- `ovk/core/router.py`
- `ovk/core/backend_registry.py`
- all production adapters’ `can_handle` implementations
- `tests/test_typed_router.py`
- `tests/test_authorization_enforcement.py`
- `tests/test_remaining_lane_enforcement.py`

### Required behavior

A candidate is eligible as required primary only when:

- `support == supported`;
- material requirements are met;
- coverage requirements are met;
- guarantee is accepted;
- budget permits execution;
- backend is allowed;
- backend is available or an accepted pre-execution fallback path exists.

When coverage is insufficient:

- candidate moves to rejected;
- rejection reason includes coverage status and warnings;
- optional corroboration is permitted only by explicit policy.

### Tests

- candidate with false coverage cannot be selected required;
- complete candidate wins over higher-scored incomplete candidate;
- all incomplete candidates produce no required selection and review;
- partial optional corroborator cannot upgrade a required unknown;
- source compiler with unsupported constructs cannot produce strict allow.

## 7.2 Reject guarantee mismatch

### Files

- `ovk/core/backend_control_plane.py`
- `ovk/core/evidence_invariants.py`
- `tests/test_adversarial_control_plane.py`

### Required behavior

Replace guarantee rewriting with explicit failure.

When:

```text
compiled.expected_guarantee != selected.expected_guarantee
```

create an execution record with:

- termination `invalid_output` or new `compiler_contract_error`;
- status `error`;
- human review;
- no backend execution;
- quality issue `OVK-INV-GUARANTEE-MISMATCH`.

### Tests

- defective adapter compiles weaker guarantee;
- defective adapter compiles unrelated guarantee;
- router selection remains unchanged but execution is rejected;
- no rewritten guarantee appears in evidence.

## 7.3 Make fallback per-backend and per-guarantee

### Files

- `ovk/core/execution_models.py`
- `ovk/core/backend_aggregation.py`
- `ovk/core/router.py`
- `schemas/backend.routing.schema.json`
- `tests/test_authorization_enforcement.py`
- `tests/test_self_protection_enforcement.py`
- new `tests/test_fallback_policy.py`

### Model change

Extend fallback policy:

```python
class AcceptedFallback(BaseModel):
    backend: str
    guarantee_type: str
    permitted_termination_causes: list[Literal["tool_unavailable"]]

class FallbackPolicy(BaseModel):
    allow_fallback: bool
    accepted: list[AcceptedFallback]
```

Do not accept timeout, tool error, invalid output, or resource exhaustion as fallback causes in the initial policy.

### Tests

- listed fallback backend and guarantee can satisfy a pre-execution unavailable primary;
- unlisted fallback backend cannot;
- listed backend with wrong guarantee cannot;
- timeout never becomes fallback pass;
- tool error never becomes fallback pass;
- evidence records fallback cause and guarantee downgrade.

## 7.4 Default self-protection metadata to untrusted

### Files

- `ovk/core/self_protection_compiler.py`
- `ovk/core/adapter_runtime.py`
- `ovk/core/context.py`
- `schemas/verification.config.schema.json`
- `tests/test_self_protection_enforcement.py`
- `tests/test_trusted_policy_loading.py`

### Required behavior

- compiler default `metadata_trusted=False`;
- runtime default false;
- trust true requires typed provenance from protected base workflow or signed service;
- current-state-only metadata cannot authorize allow;
- explicit examples and fixtures may opt in to trusted metadata only inside tests.

### Required provenance

```python
class MetadataProvenance(BaseModel):
    collector: str
    source: Literal["protected_base_workflow", "signed_service", "maintainer_input"]
    repo: str
    base_sha: str
    head_sha: str
    collected_at: str
    sha256: str
```

## Sprint 2 exit criteria

- coverage affects selection;
- guarantee mismatch cannot be hidden;
- fallback is narrowly enforced;
- self-protection trust is fail-closed by default.

# 8. Sprint 3 — Unify routing from kernel inference through evidence

## Objective

Remove the dual-route architecture.

## Files

- `ovk/core/kernel.py`
- `ovk/core/check.py`
- `ovk/core/obligation_compiler.py`
- `ovk/core/router.py`
- `ovk/core/adapter_runtime.py`
- MCP planning and execution surfaces
- CLI plan/check/run surfaces

## Required architecture

1. Build repository context.
2. Infer candidate intents.
3. Compile typed neutral obligations.
4. Route each obligation exactly once.
5. Execute those exact routing decisions.
6. Return the exact typed decisions in `KernelResult`.
7. Bind routing IDs into evidence and artifacts.

`route_intent` may remain only as:

- deprecated compatibility API;
- catalog exploration API;
- never an internal execution route.

## Kernel result model

Replace compatibility routing dictionaries with:

```python
class KernelResult(BaseModel):
    plan: VerificationPlan
    obligations: list[VerificationObligation]
    routing: list[RoutingDecision]
    execution_records: list[ObligationExecutionRecord]
    bundle: EvidenceBundle
    policy_source: PolicySource
```

## Tests

- `KernelResult.routing` IDs equal evidence routing IDs;
- denying a backend changes kernel execution;
- no second route is computed;
- CLI and MCP return the same selected/executed sets;
- routing digests remain identical through attestation;
- legacy mode is explicit and emits evidence v1 only;
- shadow mode contains both legacy and typed records with legacy authority clearly marked;
- enforced mode uses only typed control-plane results.

## Sprint 3 exit criteria

- one authoritative route exists per obligation;
- all public execution surfaces report the same route;
- no compatibility routing artifact is presented as authoritative.

# 9. Sprint 4 — Hard execution isolation

## Objective

Ensure every authoritative adapter can be cancelled and cannot inherit ambient credentials or unrestricted filesystem access.

## Files

- `ovk/core/execution_budget.py`
- new `ovk/core/backend_workers.py`
- production adapters
- worker tests

## Required worker implementations

1. `LocalSubprocessWorker`
2. `SpawnedPythonWorker`
3. interface for later `ContainerWorker`

## Required controls

- wall-time timeout;
- process termination;
- bounded stdout and stderr;
- minimal environment;
- bounded working directory;
- explicit network policy metadata;
- explicit repository-write policy;
- process exit and signal recording;
- worker identity and image/runtime version;
- secret-pattern redaction before public artifact emission.

## Deterministic adapters

Move deterministic evaluators out of the control-plane process.

Use a stable worker entry point such as:

```text
python -I -m ovk.worker evaluate --adapter <id> --input <path> --output <path>
```

The parent validates the worker output against a strict schema.

## Tests

- hanging deterministic adapter is terminated;
- child process attempting path escape is rejected;
- unknown parent credential is absent;
- explicit safe variable is available;
- oversized output is truncated and marked;
- malformed worker output becomes error;
- child process crash becomes error;
- total budget cancels remaining optional work;
- no completed result is emitted after timeout.

## Sprint 4 exit criteria

- no authoritative adapter executes unbounded in-process;
- every attempt has externally enforced termination semantics.

# 10. Sprint 5 — Evidence v3 and cross-artifact binding

## Objective

Make the complete control-plane trace mandatory and verifiable by external consumers.

## New schemas

- `verification.evidence.v3.schema.json`
- `verification.bundle.v3.schema.json`
- `material.reference.schema.json`
- `material.set.schema.json`
- `execution.attempt.schema.json`
- strengthened routing and result schemas

## Required evidence fields

For `routing_enforced: true`, require:

- obligation ID;
- routing ID;
- compiler identity;
- typed materials;
- material-set digest;
- typed coverage;
- requested candidates;
- eligible candidates with reasons;
- selected backends with required/optional roles;
- attempted backends;
- executed backends;
- execution attempts;
- guarantee classes;
- aggregation policy and reason;
- open obligations;
- policy digest;
- cache-hit state.

## Canonical material-set digest

Calculate over sorted canonical material references.

Store and verify in:

- obligation;
- evidence;
- provenance;
- attestation;
- release verifier.

## Invariant upgrades

Add canonical recomputation for:

- obligation ID;
- routing ID;
- backend obligation ID;
- attempt ID;
- material-set digest;
- selected/executed set and role consistency;
- guarantee consistency;
- aggregate decision;
- attestation bindings.

## Migration

- read v1 and v2;
- generate v3 only for new enforced execution;
- provide migration documentation;
- do not silently convert v1/v2 to v3 without preserving absent-field warnings.

## Sprint 5 exit criteria

- an external validator can reconstruct every control-plane identity;
- artifacts fail when material, route, execution, or aggregate data disagree.

# 11. Sprint 6 — Source profile hardening

This sprint must proceed as separate profile-specific pull requests.

## 11.1 FastAPI supported profile

Replace regex-only route discovery with Python AST and module resolution.

Support a documented subset:

- `FastAPI` and `APIRouter` construction;
- decorator routes;
- `include_router`;
- static prefixes;
- application, router, and route dependencies;
- imported named dependencies;
- common role predicates;
- base/head reconstruction.

Mark review for:

- dynamic route registration;
- runtime factory-generated routers;
- unresolved imports;
- arbitrary metaprogramming;
- unsupported class dependencies.

Coverage must count discovered application/router objects, include relationships, and route registrations. `expected_elements` cannot simply equal `extracted_elements`.

## 11.2 Express supported profile

Use TypeScript compiler API or ESTree-compatible parser.

Support:

- `express()`;
- `Router()`;
- static route registrations;
- middleware ordering;
- router mounts;
- import aliases;
- common auth and role middleware;
- base/head comparison.

Mark review for dynamic paths, runtime registrations, unresolved module calls, and computed middleware arrays.

## 11.3 Terraform supported profiles

Use recursive plan traversal.

Implement provider profiles separately, starting with a bounded set such as:

- AWS S3 public exposure;
- AWS security-group/network path exposure;
- selected load-balancer entry points;
- one GCP storage profile or equivalent pilot requirement.

Model:

- `resource_changes` recursively;
- module addresses;
- `after_unknown`;
- sensitive values;
- provider defaults used by the profile;
- source addresses;
- policy and network relationships.

## 11.4 Kubernetes supported profile

Resolve:

- namespace;
- Service selectors;
- workload labels;
- Ingress/Gateway backends;
- load-balancer address state;
- GatewayClass/IngressClass policy;
- NetworkPolicy intersections;
- relevant RBAC and ServiceAccount relationships.

Do not classify every Ingress as public without profile evidence.

## 11.5 GitHub Actions supported profile

Implement:

- workflow and job permission override semantics;
- event-specific secret availability;
- `pull_request_target` checkout trust;
- reusable workflow secret and permission propagation;
- `secrets: inherit`;
- local composite action expansion;
- protected environment configuration as trusted material;
- conservative `if:` evaluation;
- immutable versus mutable remote references.

## 11.6 Deployment supported profiles

Define strict profiles only over:

- explicit OVK deployment schema;
- trusted GitHub Environment metadata;
- bounded Argo Rollouts fields.

Artifact identity, approver evidence, promotion transitions, rollback reachability, and override authority must be typed materials.

## Sprint 6 exit criteria

Each source profile has:

- a versioned support contract;
- positive corpus;
- negative corpus;
- unsupported corpus;
- independent annotations;
- source-range correctness tests;
- measurable coverage;
- documented strict eligibility.

# 12. Sprint 7 — Template conformance v2

## Objective

Replace repository-link existence with semantic conformance.

## New status vocabulary

- `catalog_only`;
- `executable_advisory`;
- `source_profile_strict_eligible`;
- `externally_calibrated_strict`;
- `deprecated`.

## Required row fields

Each template row must include:

- compiler ID and version;
- supported source profile;
- material acquisition path;
- eligible backends;
- selected primary backend under test policy;
- guarantee class;
- pass fixture;
- fail fixture;
- malformed fixture;
- unknown fixture;
- timeout fixture;
- coverage fixture;
- counterexample validation;
- repair-artifact validation;
- evidence invariant references;
- package smoke reference;
- external calibration status;
- strict eligibility reason.

## Required execution

The conformance builder must run or consume machine-generated test results. File existence alone is insufficient.

## Documentation

README and status counts must derive from the generated conformance artifact.

## Sprint 7 exit criteria

- no template is marked strict eligible through path existence alone;
- every status is generated from tested semantic evidence.

# 13. Sprint 8 — Holdout prediction pipeline

## Objective

Create an end-to-end, label-separated evaluation of the exact release-candidate artifact.

## Job separation

### Prediction job

Receives:

- case inputs without labels;
- exact release-candidate wheel or immutable commit;
- source SHA;
- wheel digest;
- no label access.

Produces:

- predictions;
- prediction digest;
- execution metadata;
- artifact signature or attestation.

### Evaluation job

Receives:

- frozen holdout asset with independently recorded digest;
- predictions artifact and digest;
- label access;
- no release or repository credentials beyond asset retrieval.

Produces only aggregate metrics.

## Security requirements

- network-disabled evaluator container where possible;
- read-only holdout materials;
- no GitHub token in evaluator process;
- path-safe extraction;
- immutable asset digest;
- output schema validation;
- aggregate leakage scan;
- no case IDs or labels in public artifacts.

## Required aggregate provenance

- holdout tag;
- holdout asset SHA-256;
- prediction artifact SHA-256;
- wheel SHA-256;
- OVK source SHA;
- workflow run ID;
- evaluator image digest;
- sanitizer version.

## Sprint 8 exit criteria

- predictions are generated by exact release-candidate code;
- labels never enter prediction job;
- public output contains aggregate metrics only;
- all identities and digests are retained.

# 14. Sprint 9 — Independent consumer validation of current code

## Objective

Validate the new control-plane release candidate, not `v1.2.1`.

## Repositories

- `fraware/ovk-consumer-fastapi-terraform`
- `fraware/ovk-consumer-express-actions`

## Required update

Pin both to one of:

- immutable release-candidate tag `v1.3.0-rc.1`;
- immutable audited commit SHA.

Do not use `uses: ./`, `@main`, or `@master`.

## Required workflow scenarios

For each repository:

1. advisory pass;
2. advisory block;
3. incomplete abstraction requiring review;
4. strict block;
5. backend unavailable;
6. backend timeout;
7. policy change;
8. cache miss and cache hit identity equivalence;
9. release bundle generation;
10. comment emission;
11. check-run emission;
12. true cross-fork PR with reduced permissions;
13. published or release-candidate wheel installation;
14. generated regression artifact;
15. source-profile compiler run.

## Main-repository orchestration

Replace pin-only validation with workflow dispatch and artifact ingestion.

The main repository workflow must:

- dispatch consumer workflow by immutable ref;
- await conclusion;
- verify exact OVK pin;
- download evidence artifacts;
- verify release bundles;
- confirm expected recommendation per scenario;
- write a machine-readable validation ledger.

## Human pilot gate

Automated fixtures do not satisfy the production pilot gate.

Require per repository:

- at least 30 human-adjudicated advisory PRs;
- false-positive records;
- missed-detection records;
- unknown appropriateness;
- reviewer burden;
- final merge disposition.

## Sprint 9 exit criteria

- both consumers validate the current release-candidate artifact;
- all automated scenarios are attributable;
- cross-fork permissions are exercised, not simulated only;
- human pilot ledgers remain clearly separate from automated fixtures.

# 15. Sprint 10 — Release provenance and publication

## Objective

Create an attributable release candidate and later stable release.

## Benchmark provenance correction

Change generated benchmark fields:

- `benchmark_source_sha` — source evaluated by benchmark workflow;
- `verified_source_sha` — source with complete required workflow evidence;
- `verified_workflow_runs` — required workflow names, run IDs, and conclusions.

A benchmark-only workflow cannot populate `verified_source_sha`.

## Release-candidate gates

Require on the exact tag source:

- general CI;
- native Tier 1;
- package and isolated wheel smoke;
- Action dogfood;
- release preflight;
- template conformance v2;
- expanded FormalPR-Bench;
- holdout prediction/evaluation;
- consumer validation;
- release-bundle verification;
- keyless Sigstore signing and verification;
- tamper tests.

## Versioning

Use:

`v1.3.0-rc.1`

until all P0 and automated validation gates pass.

Promote to `v1.3.0` only after:

- current-source required workflows are green;
- both consumer repositories pass the current pin;
- holdout aggregates are attributable;
- all P0 invariants are closed;
- release status is internally consistent.

Keep package classifier Beta until human pilot thresholds and externally calibrated strict profiles are complete.

# 16. Required pull-request decomposition

Do not merge the remaining program as one monolithic change.

Use the following PR order.

## PR A — Deterministic attempt identity

- remove duration from identity;
- add determinism tests;
- no behavior changes elsewhere.

## PR B — Provenance-preserving cache v3

- cached execution model;
- cache schema bump;
- cache-hit provenance tests;
- no synthesized native state.

## PR C — Coverage and guarantee contract enforcement

- coverage-aware routing;
- guarantee mismatch failure;
- adversarial adapters and tests.

## PR D — Fallback policy v2

- per-backend and per-guarantee fallback;
- timeout/error rejection;
- schema and migration.

## PR E — Self-protection trust provenance

- trust false by default;
- provenance model;
- protected-source tests.

## PR F — Single authoritative routing pipeline

- compile before route;
- one typed route;
- CLI/MCP parity;
- legacy API deprecation.

## PR G — Isolated deterministic workers

- spawned process worker;
- migrate one deterministic adapter;
- timeout and environment tests.

## PR H — Remaining adapter isolation

- migrate all authoritative adapters;
- resource and output bounds.

## PR I — Evidence v3 and material-set binding

- schemas;
- invariants;
- provenance and attestation;
- release verifier.

## PR J — Template conformance v2

- status vocabulary;
- semantic fixtures;
- generated docs counts.

Source compiler tracks may proceed in parallel after PR F, provided they use the centrally approved obligation, material, coverage, routing, and evidence models.

# 17. Pull-request acceptance checklist

Every PR must include:

## Architecture

- explicit interfaces;
- schema version impact;
- cache impact;
- migration impact;
- trust-boundary impact;
- guarantee statement;
- known limits.

## Tests

- passing case;
- failing case;
- malformed case;
- unknown case;
- timeout case where applicable;
- deterministic identity case;
- cache case where applicable;
- evidence-quality case;
- package or Action case where public behavior changes.

## Security

- no unrestricted path extraction;
- no unbounded inherited environment;
- no implicit fallback;
- no false native claim;
- no compiler guarantee relabeling;
- no untrusted metadata treated as authoritative by default;
- no PR-controlled policy governing its own enforcement without protected-source rules.

## Artifacts

- exact subject;
- material digests;
- compiler identity;
- coverage;
- selected and executed backend roles;
- execution provenance;
- assumptions and limits;
- attestation impact.

## Documentation

- status update;
- backend maturity update;
- template conformance update;
- migration note;
- release-gate impact.

# 18. Definition of completed vision

The current OVK vision is complete only when all conditions below hold.

1. Every enforced obligation is routed exactly once.
2. `KernelResult`, evidence, provenance, and attestation reference the same routing ID.
3. Coverage requirements affect primary selection.
4. Compiler and routing guarantees cannot disagree silently.
5. Fallback is backend-, guarantee-, and cause-specific.
6. Cache hits preserve original execution provenance.
7. Attempt and bundle identities are stable across equivalent runs.
8. Every authoritative adapter is externally time-bounded.
9. Self-protection trust is explicit and protected-source-bound.
10. Evidence schema requires the complete control-plane trace.
11. Material-set digest is cross-verified across all release artifacts.
12. Strict-eligible templates pass semantic conformance, not path-existence checks.
13. Source profiles have measurable completeness and unsupported-case behavior.
14. The exact current source passes all required workflows.
15. The exact current wheel and Action pass both consumer repositories.
16. The exact current source generates holdout predictions without labels.
17. Aggregate holdout and consumer evidence is retained with immutable digests.
18. Public release claims match these artifacts.

# 19. Immediate engineer assignments

Start with these five assignments.

## Assignment 1 — Kernel identity and cache team

Deliver PR A and PR B.

Do not modify routing policy in these PRs.

## Assignment 2 — Router and aggregation team

Deliver PR C and PR D.

Use defective adapters in adversarial tests.

## Assignment 3 — Trust-boundary team

Deliver PR E and validate the worker and holdout corrections already committed during this audit.

## Assignment 4 — Kernel integration team

Design PR F after PR A–E interfaces stabilize.

Produce a design note showing how compatibility routing is removed from the authoritative execution path.

## Assignment 5 — Release and external validation team

- run the current-source baseline;
- correct benchmark source/verified source terminology;
- prepare `v1.3.0-rc.1` consumer pins;
- orchestrate consumer workflows;
- implement label-separated holdout prediction.

# 20. Final instruction

The project should now optimize for semantic integrity, not breadth.

Do not add another backend, template family, or marketing claim until:

- cached provenance is correct;
- attempt identity is deterministic;
- coverage governs selection;
- fallback is narrowly enforced;
- routing is unified;
- self-protection trust is fail-closed;
- current-source external validation exists.

The architecture is now sufficiently ambitious. The next engineering quality threshold is proving that every identity, guarantee, material, execution, and release claim remains correct under adversarial conditions.
