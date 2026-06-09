# Repository Status Analysis

This document records the current engineering status of Open Verification Kernel and the sprint plan for moving from bootstrap to a credible v0. It should be updated at the end of each implementation pass.

## Executive assessment

The repository is in a credible bootstrap-to-v0 transition state. It is no longer only a concept document. It has a clear architecture, schemas, starter package, runnable demo paths, tests, CI, seed benchmark scaffolding, a documented v0 runner design, and a closed Sprint 1 self-protection path. It is not yet a production-grade verification system. The remaining work is mainly real backend execution, richer GitHub metadata collection, PR comment posting, and further hardening of evidence semantics.

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
| Changed-file ingestion | Present | Accepts JSON, newline text, or unified diff |
| Required-check metadata loader | Present | Accepts explicit before/after required-check metadata |
| `ovk ci` | Present | Runs the Sprint 1 self-protection path |
| Composite GitHub Action | Present | Calls `ovk ci` in advisory or strict mode |
| v0 self-protection runner script | Present | Emits evidence, Markdown, and attestation from metadata |
| Benchmarks | Present | Five seed cases, including missing metadata |
| CI | Present | Runs lint, tests, seed benchmark, `ovk ci`, and artifact upload |

## Known limitations

### Metadata dependence

The Sprint 1 path can ingest changed files and required-check metadata from explicit files, but it does not yet query GitHub branch-protection settings directly. Missing required-check metadata is intentionally treated as unknown and requires human review.

### Backend execution

The OPA path currently uses deterministic Python with OPA-style semantics. A real OPA CLI integration should be added behind the same adapter interface.

The Z3 path currently uses a deterministic reachability checker and an optional Z3 helper. The next version should generate real SMT obligations and record query polarity in evidence.

### PR integration

The Action now calls `ovk ci` and the project CI uploads evidence artifacts, but PR comment posting is still not implemented. The project can render Markdown, but a GitHub API posting step remains future work.

### Benchmark depth

The seed benchmark now covers pass, fail, and unknown outcomes for the first self-protection path, plus authorization pass and fail cases. It still needs adversarial cases, weak specifications, timeout behavior, unknown solver state, and multi-backend routing.

## Sprint 1 status: closed

Goal: make one real PR-style path work end to end for workflow and verification-control changes.

### Completed

- Added repository status analysis and sprint plan.
- Hardened the self-protection adapter so missing required-check metadata on high-risk agent-authored changes returns unknown and requires human review.
- Preserved concrete failure precedence. A `.verification/` change by an AI agent still fails even when metadata is missing.
- Added `SelfProtectionMetadata` and canonical structured input builder.
- Added changed-file ingestion from JSON, newline text, and unified diff.
- Added required-check metadata normalization from explicit before/after metadata.
- Added metadata fixtures for removed gate, missing required checks, changed files, and required-check metadata.
- Added `scripts/run_v0_self_protection.py` to emit evidence, Markdown, and an unsigned attestation statement.
- Added `ovk ci` as the Sprint 1 command surface.
- Wired the composite GitHub Action to call `ovk ci`.
- Updated CI to exercise `ovk ci` and upload OVK artifacts.
- Added tests for pass, fail, unknown, configuration-change failure, structured input building, metadata composition, changed-file ingestion, runner outputs, and artifact writing.
- Added a missing-metadata seed benchmark case.
- Relaxed Ruff line length to 120 to keep bootstrap code lintable without unsafe rewrites through the connector.

### Sprint 1 exit criterion

A workflow or `.verification/` change authored by an AI agent produces one of three honest outcomes: allow, block, or require human review. Missing control metadata does not pass.

## Sprint plan

### Sprint 2: real OPA and stronger GitHub path

Goal: convert the first path from deterministic evaluator to real policy-backed execution and improve GitHub integration.

Deliverables:

- OPA CLI execution helper.
- Rego policy fixture.
- Unknown result when OPA binary or metadata is unavailable.
- Direct GitHub branch-protection and required-check metadata collection where token permissions allow it.
- Evidence and Markdown artifact flow already exists and should be hardened.
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

Sprint 1 is closed. The next priority is Sprint 2: real OPA execution behind the current self-protection adapter and stronger GitHub metadata collection without weakening the existing unknown-result discipline.
