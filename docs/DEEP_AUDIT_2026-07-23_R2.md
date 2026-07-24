# OVK Deep Audit R2 — 2026-07-23

Authoritative deep audit of Open Verification Kernel after the typed backend control-plane landing. This document supersedes day-to-day use of [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) for release judgment. The vision audit remains historical context.

Companion program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md). Living dashboard: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

## Final technical judgment

The engineers completed the most important architectural transition in the roadmap.

OVK now has a genuine typed backend control plane. In explicitly enforced lanes, a typed `RoutingDecision` identifies selected registered adapters, and those selected adapters compile and execute backend-specific obligations. The system includes backend-neutral obligations, typed routing, controlled attempts, conservative aggregation, evidence v2, five enforceable lane paths, source-compiler profiles, template conformance, consumer repositories, and holdout plumbing.

The vision is not fully achieved. Current code should be positioned as:

**An advanced, policy-selectable verification-kernel release candidate for a future `v1.3.0-rc.1`.**

The default product path remains shadow/legacy-authoritative. Enforced routing is available through lane policy, but several P0 trust properties remain incomplete.

## Audit coverage

This audit covered:

- typed execution models and digest logic;
- backend registry, router, control plane, aggregation, and cache;
- all five enforced lanes;
- OPA, Z3, CBMC, Cedar, and external adapter surfaces;
- FastAPI, Express, Terraform, Kubernetes, GitHub Actions, deployment, and CBMC compilers;
- evidence v2, quality invariants, attestations, provenance, manifests, and Sigstore;
- GitHub Action, CI, release, holdout, and consumer workflows;
- FormalPR-Bench and template-conformance artifacts;
- both external consumer repositories.

## Release provenance correction

The signed `v1.2.1` release is commit:

`a27d5720f4350c00bca34f71d991c31f5a2f38c7`

Its release workflow successfully completed release verification, package build, isolated wheel smoke, and keyless Sigstore signing.

That evidence applies only to the old tag. The typed control plane and the bulk of the current architecture were added after that commit. The two external consumer repositories also currently pin `v1.2.1`, so they validate the old release, not the newly pushed implementation.

**Do not** re-attribute `v1.2.1` Sigstore/CI evidence to typed-control-plane commits.

Latest `main` may be a benchmark badge commit marked `[skip ci]`. Generated benchmark data must not label a badge-only commit as `verified_source_sha` without a complete observed required-workflow set.

Terminology required going forward:

| Field | Meaning |
|---|---|
| `benchmark_source_sha` | Source measured by FormalPR-Bench (or similar bench artifacts) |
| `verified_source_sha` | Source with a complete observed required-workflow set |

Badge-only or `[skip ci]` commits must never be labeled verified.

## What has genuinely been achieved

### Enforced backend execution

Selected backends can now control execution within enforced lane paths. This is real, not merely metadata.

Current selectable pairs include:

- authorization through `z3-native` or `authorization-deterministic`;
- self-protection through `opa-native` or `self-protection-deterministic`;
- infrastructure, CI secrets, and deployment through registered deterministic adapters.

### Strong execution and evidence foundations

The repository now contains:

- typed verification subjects and materials;
- backend-neutral obligations;
- backend capability assessments;
- typed routing decisions;
- backend-specific obligations;
- raw executions and normalized results;
- execution budgets;
- evidence v2;
- fail-dominant aggregation;
- routing- and environment-bound cache keys;
- release manifests, provenance, attestations, HMAC, and Sigstore support.

### Honest catalog separation

The template-conformance system distinguishes five linked production lanes from 95 catalog-only templates. This is substantially more honest than presenting all 100 templates as operational. Remaining gap: `strict_eligible` is still inferred mainly from repository links, fixtures, and a test file, rather than semantic completeness.

### External consumer infrastructure exists

The FastAPI/Terraform and Express/GitHub Actions consumer repositories are real and include pinned Action workflows, scenario matrices, pilot ledgers, release-bundle paths, and wheel-install scripts. Their automated scenarios remain separate from the required human-adjudicated pilot gate.

## P0 defects remaining

### 1. Attempt IDs are nondeterministic

Execution attempt identity still includes `duration_ms`. Timing varies between otherwise equivalent runs, so attempt IDs, evidence, bundle IDs, and attestations can vary without a semantic input or output change.

**Required fix:** remove timing fields from canonical attempt identity; prove stable IDs across sequential, parallel, cached, and uncached equivalent executions.

### 2. Cache hits lose original execution provenance

The cache returns normalized results without the complete original attempt. On a cache hit, the control plane synthesizes a new attempt and may re-infer `native_execution` from current tool availability.

This can falsely describe a cached deterministic result as native after a tool is installed, or erase native tool provenance after the tool disappears.

**Required fix:** store and replay `CachedBackendExecution` with original attempt, native flag, tool version/digest, termination/exit code, raw-result digest, environment fingerprint, and normalized result. Bump cache schema to v3.

### 3. Guarantee mismatches are silently rewritten

When the router expects one guarantee and the adapter compiler produces another, the control plane rewrites the compiled obligation to the router’s expectation.

**Required fix:** treat mismatch as a compiler-contract error; skip execution; require review. Never silent `model_copy` rewrite.

### 4. Coverage does not govern backend eligibility

Adapters report `coverage_requirements_met`, but required-primary selection does not reject candidates for which this field is false.

**Required fix:** reject incomplete candidates as required primaries; allow only as optional corroborators under explicit policy. Stop hardcoding `coverage_requirements_met=True` in manifest assessment.

### 5. Fallback policy is under-specified

Aggregation receives a broad `fallback_accepted` boolean. It does not constrain fallback by backend, guarantee type, or failure cause.

**Required fix:** backend-, guarantee-, and cause-specific policy. Native timeout, tool error, invalid output, and resource exhaustion must never become passing fallback results.

### 6. Self-protection metadata defaults to trusted

Enforced self-protection currently initializes `metadata_trusted` to true unless policy explicitly sets it false.

**Required fix:** default `metadata_trusted=False`. Trust only from protected base-workflow provenance, signed service, or explicit maintainer-supplied material. Current-state-only branch protection cannot set trusted.

### 7. Deterministic adapters cannot be hard-cancelled

Several deterministic adapters execute in-process and inspect elapsed time only after returning. A hung or unexpectedly expensive evaluator cannot be terminated.

**Required fix:** every authoritative adapter must run behind a subprocess/spawned-worker boundary with wall-time, output, env, path, and hard cancellation.

### 8. Two routing paths remain

The kernel calculates compatibility routing before compiling obligations. The enforced runtime later compiles a typed obligation and calculates another typed route.

**Required fix:** compile typed obligations before routing; route each obligation exactly once; execute that immutable `RoutingDecision`; expose the same `routing_id` through kernel, CLI, MCP, evidence, provenance, and attestation.

### 9. Evidence v2 does not require the complete trace

The schema requires obligation ID, routing ID, selected and executed backends, and aggregation policy. It leaves compiler, materials, coverage, requested/eligible/attempted backends, execution attempts, and routing-enforced state optional or broadly typed.

**Required fix:** evidence v3 with mandatory full control-plane trace and one canonical material-set digest cross-bound across obligation, evidence, provenance, attestation, and release verification.

## Direct fixes required with this audit baseline

Claimed during audit authoring; must be present in tree before Sprint 0 measurement:

1. **CI-secrets / material integrity** — `size_bytes` must bind canonical serialized payload length, not digest string length.
2. **Backend worker environment** — inherit only configured safe parent vars; strip credentials; reject non-positive wall budget.
3. **FormalPR-Holdout supply-chain boundary** — immutable SHA-256, path-safe extraction, isolated Python, no tokens in evaluator, schema validation, leakage guards.

## Definition of completed vision (18-condition gate)

Ship / promote to `v1.3.0` only when all hold:

1. one route per enforced obligation;
2. the same `routing_id` across kernel, evidence, provenance, and attestation;
3. coverage-aware selection;
4. no silent guarantee mismatch;
5. constrained fallback;
6. provenance-preserving cache hits;
7. deterministic attempt identities;
8. hard-bounded adapters;
9. protected self-protection trust;
10. complete evidence trace;
11. cross-artifact material binding;
12. semantic template conformance;
13. current-source CI on a non-`[skip ci]` SHA;
14. current wheel and Action validation in both consumers;
15. label-separated holdout predictions;
16. immutable retained evaluation artifacts;
17. attributable release gates on the exact tag source;
18. correct `benchmark_source_sha` vs `verified_source_sha` terminology in published artifacts.

## Related documents

| Document | Role |
|---|---|
| [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md) | Sprint/PR execution program |
| [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) | Living adoption dashboard |
| [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) | Historical pre-control-plane audit |
| [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) | Consumer pin checklist |
| [FORMALPR_HOLDOUT_GOVERNANCE.md](FORMALPR_HOLDOUT_GOVERNANCE.md) | Holdout governance |
