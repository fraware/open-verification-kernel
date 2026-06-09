# Repository Status Analysis

This document records the current engineering status of Open Verification Kernel and the sprint plan for moving from bootstrap to a credible v0. It should be updated at the end of each implementation pass.

## Executive assessment

The repository is in a credible bootstrap-to-v0 transition state. It is no longer only a concept document. It has a clear architecture, schemas, starter package, runnable demo paths, tests, CI, seed benchmark scaffolding, and a documented v0 runner design. It is not yet a production-grade verification system. The remaining work is mainly integration, real backend execution, GitHub PR plumbing, and hardening of evidence semantics.

## Current strengths

### Architecture

The repository implements the correct architectural thesis. OVK is positioned as a solver-agnostic verification layer between AI coding agents and existing formal methods tools. It separates engineering changes, verification intents, backend-specific obligations, normalized evidence, and pull-request decisions.

### Evidence discipline

The project has adopted the correct evidence rule. Backend outcomes must preserve the difference between pass, fail, unknown, error, and skipped. Missing solver coverage, missing metadata, missing binaries, timeouts, parse failures, and unsupported theories must not become passing claims.

### First two verification paths

The first path checks whether an AI-authored change weakens the verification controls that govern its own merge. This is the strongest first demo because it is agent-native, high leverage, and easy for developers to understand.

The second path checks whether a non-admin principal can reach an admin-only route in a supplied authorization abstraction. This is the right second demo because it moves OVK from workflow configuration into semantic application risk.

### Handoff readiness

The repository already contains enough documentation, schemas, examples, tests, and implementation notes for engineers to continue without reconstructing the project vision.

## What is implemented

| Area | Current state | Assessment |
|---|---|---|
| README and project thesis | Present | Strong foundation |
| System specification | Present | Good for handoff |
| Formal specification | Present | Conservative and useful |
| Threat model | Present | Correct initial scope |
| JSON schemas | Present | Good v0 foundation |
| Python package | Present | Useful skeleton |
| Decision engine | Present | Conservative posture |
| Evidence bundle builder | Present | Content-addressed bundle IDs added |
| Markdown renderer | Present | PR-ready text generation exists |
| Attestation helper | Present | Unsigned in-toto-style statement |
| OPA-style self-protection path | Present and hardened for missing metadata | Runnable, deterministic, not real OPA yet |
| Z3-style authorization path | Present | Runnable abstraction, optional Z3 path started |
| Change detection | Present | Maps changed files to engineering surfaces |
| Diff parser | Present | Extracts changed paths from unified diff text |
| Planner | Present | Joins surfaces, intents, capabilities, and routing |
| Self-protection input builder | Present | Normalizes Sprint 1 metadata into adapter input |
| v0 self-protection runner script | Present | Emits evidence, Markdown, and attestation from metadata |
| Benchmarks | Present | Five seed cases, including missing metadata |
| CI | Present | Runs lint, tests, and seed benchmark scorer |

## Known limitations

### Fixture and metadata dependence

The current runnable checks still depend on structured inputs or metadata files. OVK does not yet inspect a real PR, query branch-protection settings, build structured input from actual repository state, and run the appropriate adapter fully automatically.

### Backend execution

The OPA path currently uses deterministic Python with OPA-style semantics. A real OPA CLI integration should be added behind the same adapter interface.

The Z3 path currently uses a deterministic reachability checker and an optional Z3 helper. The next version should generate real SMT obligations and record query polarity in evidence.

### GitHub Action and PR integration

The Action remains scaffolded. The project can render Markdown but does not yet post PR comments or upload evidence artifacts through a production Action flow.

### Benchmark depth

The seed benchmark now covers pass, fail, and unknown outcomes for the first self-protection path, plus authorization pass and fail cases. It still needs adversarial cases, weak specifications, timeout behavior, unknown solver state, and multi-backend routing.

## Sprint 1 status

Goal: make one real PR-style path work end to end for workflow and verification-control changes.

### Completed

- Added repository status analysis and sprint plan.
- Hardened the self-protection adapter so missing required-check metadata on high-risk agent-authored changes returns unknown and requires human review.
- Preserved concrete failure precedence. A `.verification/` change by an AI agent still fails even when metadata is missing.
- Added `SelfProtectionMetadata` and canonical structured input builder.
- Added metadata fixtures for removed gate and missing required checks.
- Added `scripts/run_v0_self_protection.py` to emit evidence, Markdown, and an unsigned attestation statement.
- Added tests for pass, fail, unknown, configuration-change failure, and structured input building.
- Added a missing-metadata seed benchmark case.
- Relaxed Ruff line length to 120 to keep bootstrap code lintable without unsafe rewrites through the connector.

### Remaining in Sprint 1

- Add direct PR changed-file ingestion using GitHub metadata or local `git diff`.
- Add branch-protection and required-check metadata collection.
- Add a single `ovk ci` command that wraps the v0 runner.
- Wire the GitHub Action to call the v0 runner once connector or manual edit path allows it.
- Upload evidence and Markdown artifacts in CI.

### Sprint 1 exit criterion

A workflow or `.verification/` change authored by an AI agent must produce one of three honest outcomes: allow, block, or require human review. Missing control metadata must not pass.

## Sprint plan

### Sprint 2: real OPA and GitHub Action path

Goal: convert the first path from deterministic evaluator to real policy-backed execution and wire it into the Action.

Deliverables:

- OPA CLI execution helper.
- Rego policy fixture.
- Unknown result when OPA binary or metadata is unavailable.
- GitHub Action calls OVK runner.
- Evidence and Markdown uploaded as artifacts.
- Optional PR comment posting.

### Sprint 3: real Z3 authorization path

Goal: make the second demo a true SMT-backed semantic check.

Deliverables:

- SMT obligation object.
- Z3 encoding for admin-route reachability.
- Model-to-counterexample translation.
- Query polarity in evidence.
- Regression test generation from counterexample.

### Sprint 4: infrastructure exposure path and benchmark hardening

Goal: show the platform and security value of OVK beyond application code.

Deliverables:

- Infrastructure graph abstraction.
- Public sensitive-resource check.
- OPA or graph-backed evaluator.
- Adversarial benchmark cases for missing metadata, unknowns, and vacuity.

### Sprint 5: attestation and release hardening

Goal: make v0 credible externally.

Deliverables:

- Content-addressed evidence statement.
- DSSE-compatible envelope support.
- Optional Sigstore integration.
- Release docs and example repository.
- v0.1 tag preparation.

## Current priority

The immediate priority remains Sprint 1. The most important engineering rule for this sprint is conservative evidence handling. If OVK detects a high-risk candidate intent but cannot build sufficient structured input, it must require human review instead of returning allow.
