# Open Verification Kernel Post-Merge Deep Audit

**Date:** 2026-07-23  
**Repository:** `fraware/open-verification-kernel`  
**Primary engineer merge:** `a87a9de99b77bf25a4ce058642a35f42ab3cd075`  
**Audited source after corrective commits:** through `5507de3d2903532f3165c09be95d46392fa93b4b`

## Executive judgment

The engineer push is a major architectural advance. OVK now contains a genuine typed backend control plane, backend registry, backend-neutral obligations, versioned routing decisions, backend-specific compilation, controlled execution records, fail-dominant aggregation, evidence v2 fields, five enforceable lane adapters, source-compiler scaffolding, a template conformance matrix, holdout evaluation plumbing, independent-consumer pin checks, and substantially improved CI organization.

The central conclusion from the previous audit must therefore be revised.

**Backend routing is no longer merely descriptive at the typed control-plane layer.** `BackendControlPlane.execute` retrieves and executes only adapters contained in `RoutingDecision.selected`, and tests demonstrate that changing the allowed backend changes the backend that runs. The five production lanes have explicit enforced runners.

The complete product path has not yet reached the full vision. The default repository policy remains a shadow migration policy. `execute_kernel` still computes a separate legacy capability-manifest route before compiling obligations, and enforced runners compute a second typed route. Source-grounded compilers remain materially narrower than their names and strict-eligibility labels suggest. Independent consumer and holdout validation are wired but not yet executed end to end. Current post-audit code has not yet produced an observed green CI and native Tier 1 run.

**Current release judgment:** advanced v1.2.1 release candidate with an implemented enforcement control plane, pending semantic hardening, routing unification, post-audit CI, and independent external validation.

OVK has achieved the architectural core of a solver-aware verification kernel. It has not yet achieved broad, source-complete, independently validated solver-agnostic enforcement.

---

## 1. Audit basis

This audit reviewed:

- the complete PR #12 merge and its changed-file set;
- typed execution models and digest surfaces;
- backend adapter contract and registry;
- typed and compatibility routers;
- backend control-plane compilation, caching, execution, normalization, and aggregation;
- migration integration in `adapter_runtime` and `kernel`;
- all five enforced production lanes;
- OPA, Z3, CBMC, Cedar, and external adapter maturity;
- FastAPI, Express, Terraform, Kubernetes, GitHub Actions, deployment, and CBMC compiler paths;
- evidence v2, invariants, attestation, provenance, manifests, envelopes, and release validation;
- template conformance generation;
- FormalPR-Holdout runner and workflow;
- independent-consumer pin workflow;
- general CI, native Tier 1 CI, package smoke, Action dogfood, release, and Sigstore evidence;
- public status and README claims.

The audit used the GitHub repository and Actions APIs. Local cloning and direct test execution were unavailable in the audit environment. General CI on the PR head was observed green. Native Tier 1 on the same PR head was observed failing for OPA and CBMC. Later engineer commits claimed fixes for those failures, but no post-fix green native run was observed during this audit. All corrective commits made during the audit require a fresh CI run.

---

## 2. What the engineers genuinely achieved

### 2.1 Typed backend control plane

The repository now has explicit models for:

- verification subjects;
- material references;
- abstraction coverage;
- backend-neutral obligations;
- backend capability assessments;
- routing decisions;
- backend-specific obligations;
- raw executions;
- execution attempts;
- normalized results;
- aggregate execution records;
- execution budgets and environment fingerprints.

Canonical digest functions exist for obligation, routing, backend obligation, raw output, and environment identity. This is a credible control-plane data model.

### 2.2 Registry-controlled adapter execution

`BackendRegistry` validates adapter identity and capability manifests, rejects duplicate backend and adapter IDs, orders adapters deterministically, and exposes typed capability assessment.

`BackendControlPlane`:

1. iterates the selected backend set;
2. requires a registered adapter;
3. compiles a backend-specific obligation;
4. fingerprints the execution environment;
5. retrieves only routing- and environment-bound cached results;
6. executes the selected adapter;
7. records an execution attempt;
8. normalizes the backend result;
9. aggregates selected results.

An adapter exception becomes explicit error evidence. An absent adapter does not silently fall back to an unrelated backend.

### 2.3 Five enforced lane paths

The runtime includes enforced paths for:

- self-protection;
- authorization;
- infrastructure exposure;
- CI secret exposure;
- deployment approval state.

Authorization has two distinct selectable implementations:

- `z3-native`;
- `authorization-deterministic`.

Self-protection has:

- `opa-native`;
- `self-protection-deterministic`.

Infrastructure, CI secrets, and deployment currently each have one deterministic enforced backend. This is still valuable: the control plane genuinely selects and executes a registered backend, even where only one implementation is currently eligible.

### 2.4 Conservative aggregation

The versioned `ovk.aggregate.fail_dominant.v1` policy implements the correct high-level hierarchy:

- any required or optional corroborating fail blocks;
- required unknown, error, skipped, or timeout requires review;
- optional pass cannot upgrade a required unknown;
- missing required results require review;
- unacceptable guarantee classes require a stronger check;
- all required passing results with accepted guarantees can allow.

During this audit, aggregation was corrected so an extra unselected backend result is a quality error. The previous subset test rejected missing selected results but accepted unexpected additional results.

### 2.5 Evidence v2 and artifact expansion

Enforced execution produces evidence with:

- obligation ID;
- routing ID;
- compiler identity;
- material references;
- coverage record;
- requested, eligible, selected, attempted, and executed backend sets;
- execution attempts;
- aggregation policy;
- `routing_enforced: true`.

Attestation statements and provenance now include major control-plane identities and summaries. Release output validation rejects a quality report whose semantic `passed` field is false.

### 2.6 Source-compiler foundations

The engineer push added structured compiler packages for:

- FastAPI authorization;
- Express authorization;
- Terraform plan input;
- Kubernetes objects;
- GitHub Actions trust flow;
- explicit deployment policy;
- GitHub Environments;
- Argo Rollouts;
- CBMC project registration and harness traceability.

These are useful intermediate representations and establish a scalable package structure. They are not all strict-grade yet; the limitations are detailed below.

### 2.7 Honest template catalog separation

The generated template conformance artifact reports:

- 100 catalog templates;
- 95 `catalog_only` templates;
- five templates with complete declared executable links.

This is a major improvement over presenting every template as operational.

### 2.8 CI and package evidence

General CI on PR head `fb371cdb684a973eb289fa4e0dc6e986bcec56dd` was observed green for:

- unit and integration tests;
- lint;
- package build;
- installed-wheel smoke outside the checkout;
- automatic-diff Action dogfood;
- strict-block Action dogfood;
- release gates;
- expanded benchmark;
- release bundle validation;
- template conformance.

Release run `30010876652` for v1.2.1 was observed green for release verification, isolated wheel smoke, and keyless Sigstore sign/verify. PyPI publication was skipped.

---

## 3. Correctness defects fixed during this audit

### 3.1 Unexpected backend aggregation

**Defect:** the aggregate mismatch condition accepted additional unselected executed backends.

**Fix:** selected and executed sets must now be exactly equal. Missing and unexpected backends are reported separately and force human review with a quality error.

**Files:**

- `ovk/core/backend_aggregation.py`
- `tests/test_backend_aggregation_unselected.py`

### 3.2 Native Tier 1 summary masking matrix failures

**Defect:** `native-tier1-summary` used `if: always()` and succeeded even when required OPA or CBMC matrix jobs failed.

**Fix:** the summary still emits diagnostics but now fails unless `needs.native-backend-tier1.result == success`.

**File:** `.github/workflows/native-backends-tier1.yml`

### 3.3 Legacy backend-name migration

**Defect:** `ovk init` generated `[opa, z3, cedar]`, while the typed control plane registers IDs such as `opa-native`, `z3-native`, and lane-specific deterministic adapters. Existing starter policy could silently exclude the new control plane.

**Fix:** backend policy aliases are canonicalized. The exact historical starter allowlist is interpreted as its intended unrestricted migration default. Explicit short aliases expand to their canonical control-plane IDs.

**Files:**

- `ovk/core/backend_ids.py`
- `ovk/core/context.py`
- `ovk/core/execution_budget.py`
- `tests/test_backend_policy_aliases.py`

### 3.4 Material byte-size integrity

**Defect:** several compilers set `MaterialReference.size_bytes` to `len(sha256_hex_digest)`, generally 64, instead of the number of serialized material bytes.

**Fix:** canonical material serialization and construction are centralized. Authorization, infrastructure, deployment, self-protection, and CBMC compilers use the canonical constructor.

**Files:**

- `ovk/core/materials.py`
- `ovk/core/authorization_compiler.py`
- `ovk/core/infrastructure_compiler.py`
- `ovk/core/deployment_compiler.py`
- `ovk/core/self_protection_compiler.py`
- `ovk/core/cbmc_compiler.py`
- `tests/test_material_reference_sizes.py`

**Remaining exception:** the CI-secrets compiler and the deprecated helper in `compiler_bridge.py` still require migration. The direct rewrite was blocked by connector safety controls and was not forced.

### 3.5 Migration cache isolation

**Defect:** the flat evidence cache was read before routing mode was resolved. Its key omitted policy content and routing mode. A cached legacy result could bypass a later enforced execution.

**Fix:**

- flat evidence cache is now legacy-mode-only;
- shadow and enforced modes use the routing-bound hardened control-plane cache;
- repository policy, lane-policy text, input format, and routing mode participate in the legacy key;
- the requested `cache_dir` is propagated to control-plane execution;
- enforced evidence no longer receives a second compatibility routing artifact;
- authoritative v2 evidence retains its typed evidence identity.

**Files:**

- `ovk/core/adapter_runtime.py`
- `tests/test_runtime_cache_regimes.py`

### 3.6 Protected policy acquisition

**Defect:** `.verification/config.yml` was loaded from the pull-request workspace. A PR could influence its own routing, budget, coverage, and fallback policy before self-protection evidence was evaluated.

**Fix:** when the policy file changes, OVK reads the base-revision policy with `git show`. If trusted base material is unavailable or invalid, OVK uses a conservative built-in policy and records the policy source.

**Files:**

- `ovk/core/context.py`
- `tests/test_trusted_policy_loading.py`

---

## 4. Remaining P0 defects and architectural gaps

### 4.1 Dual routing remains in the kernel

`execute_kernel` still performs a legacy route through `IntentRegistry`, static capability manifests, and `route_intent`. It compiles lane obligations separately. Enforced lane runners then compile a typed obligation and call `route_obligation` a second time.

Consequences:

- `KernelResult.routing` may not describe the route that produced enforced evidence;
- CLI and MCP plan output can report a compatibility backend set different from the authoritative selected backend set;
- router scoring is duplicated;
- policy normalization can diverge between the two paths;
- routing is not yet one immutable plan object from inference through attestation.

**Required resolution:** compile typed neutral obligations first, route each obligation exactly once, execute those routing decisions, and return the actual `RoutingDecision` objects in `KernelResult`. Retain `route_intent` only as a deprecated compatibility API.

### 4.2 Default product path remains shadow

The typed control plane is implemented, but the default routing mode is shadow and enforced execution requires `enforced_lanes`.

This is an appropriate migration default. It also means a normal new consumer is still governed by legacy evidence unless policy opts in. The product must not claim that every default check uses selected-backend enforcement.

**Required resolution:** establish per-lane shadow-agreement thresholds and graduate lanes individually. Do not switch all lanes globally.

### 4.3 Lane-specific infrastructure policy is not compiled into enforced execution

Legacy infrastructure evaluation accepts a lane-specific policy file. The enforced infrastructure compiler and deterministic adapter do not receive the parsed `InfraExposurePolicy`; the adapter calls the default policy.

The outer cache now binds lane-policy text, but execution semantics do not.

**Required resolution:**

- load and validate the lane policy as a trusted material;
- include it in `VerificationObligation.materials` and abstraction;
- include it in the backend-specific payload;
- construct `InfraExposurePolicy` from the payload;
- attest the exact policy digest;
- add a test where changing blocked sensitivities changes the enforced decision.

### 4.4 Evidence v2 schema is weaker than the model

The v2 JSON schema requires obligation ID, routing ID, selected/executed backend sets, and aggregation policy. It does not require:

- compiler identity;
- materials;
- coverage;
- requested and eligible backends;
- attempted backends;
- execution attempts;
- routing-enforced state.

Nested objects accept broad arbitrary fields. Runtime invariants compensate partially, but external schema consumers can accept incomplete evidence.

**Required resolution:** create v2.1 or v3 schemas that reference the typed material, coverage, routing, and execution schemas and require the complete control-plane trace.

### 4.5 Cross-artifact material binding is absent

Evidence embeds compiler-created material references. Provenance separately hashes paths passed to the release-bundle writer. The verifier does not prove that the evidence materials, provenance materials, obligation materials, and attested materials are the same set.

**Required resolution:** define a canonical `material_set_digest`, place it in obligation, evidence, provenance, and attestation, and verify equality during release-bundle validation.

### 4.6 In-process execution cannot be hard-cancelled

Deterministic lane adapters execute in-process. Their timeout is checked after the evaluator returns. This is acceptable for small current evaluators but does not enforce the declared wall-time budget against a hanging or unexpectedly expensive adapter.

**Required resolution:** move every authoritative adapter execution behind a worker boundary. Use subprocess/process isolation for deterministic adapters as well as native tools. Enforce memory, filesystem, environment, output, and wall-time limits outside adapter code.

### 4.7 Current post-audit source has no observed green CI

The general CI run observed green predates the corrective commits in this audit. Native Tier 1 failed on the PR head, and later backend fixes plus the summary-gate fix have not been observed in a green run.

**Required resolution:** run all required workflows on an exact non-badge source commit after the audit fixes. Record source SHA, run IDs, job conclusions, and retained artifacts.

---

## 5. Semantic compiler assessment

### 5.1 Authorization

The FastAPI and Express packages create useful base/head IRs, source ranges, route records, dependencies, mounts, warnings, and unsupported markers.

The implementations are regex-based rather than AST/module-graph compilers.

FastAPI limitations include:

- bounded body inspection after function definitions;
- no Python import resolution;
- no complete dependency graph;
- incomplete `include_router` and nested-router composition;
- no class-based dependencies or runtime factory semantics;
- no proof that all routes were discovered.

Express limitations include:

- comma splitting of middleware arguments;
- no JavaScript or TypeScript AST;
- incomplete imported alias and re-export resolution;
- incomplete router mounting and nested middleware composition;
- no complete control-flow or dynamic registration model.

The coverage policy labels an extraction complete when base and head exist and no known unsupported pattern was detected. For regex extraction, absence of a recognized warning is not evidence that all relevant constructs were found.

**Judgment:** source-referenced advisory compiler. Not yet strict-grade for general FastAPI or Express repositories.

### 5.2 Infrastructure

Terraform consumes `terraform show -json` shaped input and avoids treating regex as authoritative. This is a strong boundary choice.

Current limits:

- only top-level `resource_changes` are walked;
- child modules and deeply nested planned values are incomplete;
- unknown values and sensitivity metadata are not fully modeled;
- provider-specific defaults are absent;
- IAM, security groups, route tables, load balancer listeners, and service relationships are not resolved;
- exposure is inferred from a small set of generic fields and explicit hints.

Kubernetes recognizes several kinds, but:

- every Ingress is treated as public;
- Gateway listener and class semantics are incomplete;
- NetworkPolicy and RBAC are stored but do not constrain reachability;
- selectors, namespaces, Services, Endpoints, routes, and policy intersections are not resolved into a full graph;
- provider/controller behavior is absent.

**Judgment:** useful normalized advisory profiles. Strict eligibility must be provider- and profile-specific.

### 5.3 GitHub Actions

The trust-flow compiler introduces the correct conceptual property: untrusted code must not execute with protected secrets, write tokens, protected environments, or privileged capabilities.

Current limits:

- workflow-level permission analysis is stronger than job-level propagation;
- any named environment is treated as protected;
- event-specific secret availability is simplified;
- `if:` conditions are not semantically evaluated;
- reusable child workflow permissions and secrets are collected but not fully propagated into parent findings;
- remote action/workflow code is not resolved and modeled;
- checkout repository/ref trust is incomplete;
- expression evaluation is pattern-based.

**Judgment:** valuable advisory trust detector. Not yet a complete GitHub Actions trust semantics engine.

### 5.4 Deployment

Explicit schema, GitHub Environment, and Argo Rollout representations establish a useful canonical state-machine direction.

Remaining requirements include:

- complete environment reviewer semantics;
- artifact identity and promotion binding;
- external deployment-controller state;
- rollback viability and evidence;
- emergency override authority;
- progressive rollout measurements and abort conditions;
- provider API acquisition.

**Judgment:** bounded deterministic state-machine verification over supplied abstractions.

### 5.5 CBMC

The CBMC track now distinguishes explicit harness, generated/template harness, and project-grounded registration. This is honest.

Project-grounded strict verification still requires:

- complete compile database acquisition;
- source and header closure;
- changed-function mapping;
- environment models;
- harness generation tied to actual functions;
- unwind sufficiency;
- architecture and define binding;
- source-to-counterexample traceability;
- project compilation inside an isolated worker.

**Judgment:** strong harness/provenance foundation, incomplete project verifier.

---

## 6. Template conformance assessment

The conformance matrix correctly prevents 95 catalog templates from being presented as executable.

Its current `strict_eligible` test is based on the existence of seven repository paths:

- intent file;
- lane evaluator;
- neutral compiler;
- backend registry;
- pass example;
- fail example;
- enforcement test.

It does not verify:

- malformed and unknown fixtures;
- source-material acquisition;
- compiler coverage guarantees;
- selected-versus-executed backend identity;
- native versus deterministic guarantee strength;
- counterexample correctness;
- release-artifact invariants;
- external calibration.

**Judgment:** executable-link conformance, not strict-semantic conformance.

The status vocabulary should be refined or the strict gate strengthened. Recommended statuses:

- `catalog_only`;
- `executable_advisory`;
- `source_profile_strict_eligible`;
- `externally_calibrated_strict`;
- `deprecated`.

---

## 7. Holdout and external validation assessment

### 7.1 FormalPR-Holdout

The runner is carefully fail-closed against label leakage and emits aggregate metrics only. It downloads a frozen release, invokes its evaluator, validates leakage guards, and refuses pass-rate-only output.

The workflow does not generate predictions. It consumes a workspace prediction file or an uploaded artifact.

**Judgment:** secure evaluator plumbing. No evidence yet that the current OVK wheel or Action generated predictions against the protected cases.

Required end-to-end design:

1. protected case-only artifact is supplied to an isolated prediction job;
2. exact OVK wheel/commit generates predictions without labels;
3. predictions are signed or digested;
4. evaluator job receives predictions and labels separately;
5. aggregate output is retained with source SHA, wheel digest, holdout tag, and prediction digest.

### 7.2 Independent consumers

The consumer-pin workflow checks two repository names for immutable Action pins and forbids `uses: ./`.

It does not:

- dispatch consumer workflows;
- inspect consumer run conclusions;
- download consumer artifacts;
- verify recommendations;
- install the released wheel independently;
- test fork permissions;
- ingest adjudicated pilot records.

**Judgment:** pin-policy check, not consumer validation.

---

## 8. Release and documentation assessment

The current release status contains post-merge contradictions:

- it states control-plane enforcement exists;
- its first gap still says routing does not control execution;
- it references an older audit as authoritative;
- it retains a v1.2.0 heading in v1.2.1 release gates.

README language remains somewhat broader than implementation. “The right checker” diagram and “every PR” language should be qualified by the five supported profiles, default shadow mode, and catalog-versus-executable distinction.

A new status document must distinguish:

1. control-plane mechanics implemented;
2. lane enforcement available by policy;
3. source semantics strict-grade or advisory;
4. external validation complete or pending;
5. exact verified source SHA and workflow runs.

---

## 9. Updated vision-achievement matrix

| Capability | Status | Judgment |
|---|---|---|
| Typed neutral obligation | Achieved for production lanes | Strong architecture |
| Typed backend registry | Achieved | Strong |
| Backend selection controls execution | Achieved inside enforced control plane | Real, tested |
| Default product enforcement | Partial | Shadow by default, lane opt-in |
| Single authoritative route from kernel to evidence | Not achieved | Legacy and typed routes coexist |
| Conservative aggregation | Achieved with audit fix | Strong |
| Routing-bound backend cache | Achieved | Strong |
| Migration-level cache isolation | Achieved with audit fix | Strong |
| Trusted policy acquisition | Achieved for changed config with audit fix | Base revision or safe fallback |
| Evidence v2 generation | Achieved | Schema needs strengthening |
| Cross-artifact material binding | Not achieved | P0 |
| Hard execution isolation | Partial | Subprocess worker exists; in-process adapters remain |
| Authorization source semantics | Partial | Regex, advisory-grade |
| Terraform/Kubernetes semantics | Partial | Profile-limited |
| GitHub Actions trust semantics | Partial | Conservative advisory detector |
| Deployment source semantics | Partial | Supplied IR profiles |
| Project-grounded CBMC | Partial | Registration/harness foundation |
| 100-template honest catalog | Achieved | 95 catalog-only |
| Strict template conformance | Not achieved | File-existence gate only |
| Internal benchmark | Achieved | Regression, not external accuracy |
| Holdout evaluator | Achieved | Prediction generation missing |
| Independent consumer validation | Not achieved | Pin check only |
| Current post-audit CI | Not observed | Must run |
| Native Tier 1 required gate | Corrected during audit | Must rerun green |

---

## 10. Final verdict

The engineers completed the most important architectural transition from the previous roadmap: OVK now possesses a genuine typed backend control plane in which a typed `RoutingDecision` can determine which registered adapter executes.

The vision is therefore no longer blocked primarily by absence of a control plane. It is blocked by integration and semantic maturity:

- the kernel still has two routing paths;
- default execution remains shadow;
- source compilers can overstate completeness;
- strict eligibility is based on executable-link presence;
- policy and artifact trust need further binding;
- holdout and consumer validation are not end-to-end;
- current post-audit CI has not been observed.

The correct positioning is:

> OVK v1.2.1 is an advanced release candidate with an implemented solver-aware backend control plane, five enforceable bounded lanes, evidence v2, and strong release-artifact foundations. Broad solver-agnostic strict enforcement remains incomplete until routing is unified, source profiles become semantically complete, artifacts are cross-bound, execution is isolated, and external evaluation is completed.

The accompanying engineering program defines the remaining work and acceptance gates.
