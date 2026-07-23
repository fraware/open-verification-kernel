# OVK Release Status

Living release and adoption dashboard for Open Verification Kernel.

**Last updated:** 2026-07-23

## Release judgment

The currently published and signed release is `v1.2.1` at commit:

`a27d5720f4350c00bca34f71d991c31f5a2f38c7`

Release workflow run `30010876652` successfully completed release verification, package build, isolated wheel smoke, and keyless Sigstore signing for that tag. PyPI publication was skipped.

Current `main` is a post-v1.2.1 development line. It adds the typed backend control plane, enforced lane adapters, source compilers, evidence v2, template conformance, holdout infrastructure, consumer validation scaffolding, and later audit fixes. The v1.2.1 run does not validate these post-tag changes.

**Current-main judgment:** advanced release candidate for a future `v1.3.0-rc.1`, pending P0 trust fixes and current-source CI.

Authoritative current audit:

- [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md)

Standalone engineer instructions:

- [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md)

## At a glance

| Signal | Current state |
|---|---|
| **Published/signed release** | `v1.2.1` at `a27d572…`; valid evidence for the previous release only |
| **Current development line** | Post-v1.2.1 control-plane architecture; requires a new release-candidate cycle |
| **FormalPR-Bench** | Repository snapshot reports 130/130 curated regression cases; internal conformance, not external accuracy |
| **Production lanes** | Self-protection, authorization, infrastructure, CI secrets, deployment |
| **Backend routing** | Typed routing controls execution inside explicitly enforced lane paths |
| **Default routing mode** | Shadow; legacy evidence remains authoritative unless lanes are explicitly enforced |
| **Native semantic paths** | OPA and Z3; CBMC supports bounded explicit/template harness paths |
| **Deterministic adapters** | Five lane implementations plus external contract adapters |
| **Current-source CI** | Must be rerun after the latest engineer and audit changes |
| **Independent consumers** | Two public consumer repositories exist, but they currently pin `v1.2.1`, not current `main` |
| **Holdout** | Evaluator plumbing exists; prediction/evaluation separation and current-wheel evaluation remain incomplete |
| **Package status** | Beta |

OVK is not complete formal verification of arbitrary code. It provides conservative verification evidence for bounded, explicitly modeled risk profiles.

## What is now achieved

- typed backend-neutral obligations;
- typed capability assessment and routing decisions;
- registry-controlled selected backend execution;
- five lane-specific enforced paths;
- fail-dominant aggregation;
- evidence v2 generation;
- routing- and environment-bound cache keys;
- source compiler packages;
- template catalog separation;
- manifests, provenance, attestations, HMAC, and Sigstore support;
- automatic GitHub Action PR-diff collection;
- two independent consumer repositories and immutable-pin checks.

## Current P0 gaps

1. Execution-attempt identity includes nondeterministic duration data.
2. Cache hits do not preserve the original execution attempt and can reconstruct native provenance from current tool availability.
3. Compiler/backend guarantee mismatch is silently rewritten instead of rejected.
4. Required-primary selection does not enforce `coverage_requirements_met`.
5. Fallback acceptance is not constrained to configured backend, guarantee, and failure cause.
6. Self-protection metadata is trusted by default unless policy explicitly disables trust.
7. Deterministic in-process adapters cannot be hard-cancelled.
8. Kernel inference and enforced execution still use separate routing paths.
9. Evidence v2 schema and invariants do not fully recompute and cross-bind routing, attempts, aggregate decisions, and materials.
10. Lane-specific infrastructure policy is not fully compiled into enforced execution semantics.
11. Source compilers remain advisory/profile-limited despite some `strict_eligible` labels.
12. Template strict eligibility is based primarily on executable-link presence.
13. Consumer repositories validate the previous release tag rather than current control-plane source.
14. Current source lacks attributable release-candidate CI, native-backend, consumer, and holdout evidence.

## Direct audit fixes now on current main

- CI-secrets material byte size now binds canonical serialized bytes.
- Backend subprocess workers inherit only a minimal allowlisted environment.
- Unknown ambient credentials are excluded from backend workers.
- Non-positive backend timeout prevents execution.
- Remote FormalPR-Holdout assets require an independently supplied SHA-256.
- Holdout archive extraction rejects traversal, links, devices, and special files.
- Downloaded holdout evaluators run without GitHub or holdout tokens.
- Holdout aggregates receive full JSON-schema and leakage-guard validation.

These fixes require a fresh current-source CI run.

## Adoption readiness

| Mode | Recommendation | Conditions |
|---|---|---|
| **Local/demo** | Appropriate after current-source CI | Inspect assumptions, limits, and profile coverage |
| **Shadow Action** | Appropriate after current-source CI | Compare typed and legacy results; retain disagreements |
| **Advisory enforced lane** | Controlled pilots only | Explicit lane policy, trusted materials, coverage review |
| **Strict required check** | Repository/profile-specific | P0 fixes, calibrated source profile, protected policy and metadata |
| **Production-stable general enforcement** | Not yet | Current-source release evidence, semantic profiles, holdout, consumer pilots |

## Release path

The next release should use a new release-candidate version such as:

`v1.3.0-rc.1`

Before that tag:

- [ ] close execution identity and cache provenance defects;
- [ ] enforce coverage and guarantee contracts;
- [ ] implement constrained fallback semantics;
- [ ] default self-protection metadata to untrusted;
- [ ] unify kernel routing;
- [ ] hard-isolate authoritative adapters;
- [ ] strengthen evidence and cross-artifact material binding;
- [ ] run current-source general and native CI;
- [ ] update both consumer repositories to the immutable release-candidate pin;
- [ ] dispatch and verify consumer scenarios;
- [ ] generate label-separated holdout predictions from the exact release-candidate artifact;
- [ ] retain exact source SHA, workflow IDs, wheel digest, Action artifacts, and signing bundles.

## Related documents

| Document | Purpose |
|---|---|
| [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md) | Fresh independent code, artifact, release, and vision audit |
| [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md) | Standalone implementation instructions and acceptance gates |
| [POST_MERGE_DEEP_AUDIT_2026-07-23.md](POST_MERGE_DEEP_AUDIT_2026-07-23.md) | Earlier post-merge audit, retained for history |
| [BACKENDS.md](BACKENDS.md) | Backend execution maturity |
| [RELEASE.md](RELEASE.md) | Release procedure |
| [FORMALPR_HOLDOUT_GOVERNANCE.md](FORMALPR_HOLDOUT_GOVERNANCE.md) | Holdout governance |
| [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) | Consumer validation checklist |
