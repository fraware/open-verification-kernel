# Repository Status Analysis

This document records the current engineering status of Open Verification Kernel and the sprint plan for moving from bootstrap to a credible v0. It should be updated at the end of each implementation pass.

## Executive assessment

The repository is in a credible bootstrap-to-v0 transition state. It is no longer only a concept document. It has a clear architecture, schemas, starter package, runnable demo paths, tests, CI, seed benchmark scaffolding, a documented v0 runner design, a closed Sprint 1 self-protection path, substantial Sprint 2 GitHub and OPA integration work, and initial Sprint 3 authorization-obligation foundations. It is not yet a production-grade verification system. The remaining work is mainly full backend execution, external smoke testing, deeper authorization solving, and release hardening.

## Current strengths

### Architecture

The repository implements the correct architectural thesis. OVK is positioned as a solver-agnostic verification layer between AI coding agents and existing formal methods tools. It separates engineering changes, verification intents, backend-specific obligations, normalized evidence, and pull-request decisions.

### Evidence discipline

The project has adopted the correct evidence rule. Backend outcomes must preserve the difference between pass, fail, unknown, error, and skipped. Missing solver coverage, missing metadata, missing binaries, timeouts, parse failures, and unsupported theories must not become passing claims.

### First two verification paths

The first path checks whether an AI-authored change weakens the verification controls that govern its own merge. This is the strongest first demo because it is agent-native, high leverage, and easy for developers to understand.

The second path checks whether a non-admin principal can reach an admin-only route in a supplied authorization abstraction. Sprint 3 has started moving this path from fixture checking toward explicit authorization obligations and solver-independent SMT planning.

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
| OPA-style self-protection path | Present and hardened | Deterministic default with Rego fixture and optional OPA runner |
| Backend strategy support | Present | `deterministic`, `opa`, and `both` exposed in CLI and Action |
| GitHub event parser | Present | Extracts repository, PR number, actor, head SHA, and base SHA |
| GitHub API metadata collector | Present | Conservative branch-protection collector returning empty metadata when unavailable |
| PR comment posting | Present | Optional update-in-place behavior with an OVK marker |
| Z3-style authorization path | Present | Runnable abstraction plus obligation and SMT-plan foundations |
| Authorization obligation model | Present | Explicit obligation ID, query polarity, routes, and witnesses |
| Solver-independent SMT plan | Present | Clause plan for future Z3 executor |
| Change detection | Present | Maps changed files to engineering surfaces |
| Diff parser | Present | Extracts changed paths from unified diff text |
| Planner | Present | Joins surfaces, intents, capabilities, and routing |
| Self-protection input builder | Present | Normalizes Sprint 1 metadata into adapter input |
| Changed-file ingestion | Present | Accepts JSON, newline text, or unified diff |
| Required-check metadata loader | Present | Accepts explicit and GitHub-shaped before/after required-check metadata |
| `ovk ci` | Present | Runs the self-protection path and accepts GitHub event payloads |
| Composite GitHub Action | Present | Calls `ovk ci`, supports comments and backend strategies |
| v0 self-protection runner script | Present | Emits evidence, Markdown, and attestation from metadata |
| Benchmarks | Present | Five seed cases, including missing metadata |
| CI | Present | Runs lint, tests, seed benchmark, `ovk ci`, and artifact upload |

## Known limitations

### Metadata dependence

The self-protection path can ingest GitHub event metadata and GitHub-shaped branch-protection metadata. It also includes a conservative GitHub API collector, but the Action does not yet collect live branch metadata automatically by default. Missing required-check metadata is intentionally treated as unknown and requires human review.

### Backend execution

The OPA path includes a Rego policy fixture, optional OPA runner, OPA evidence normalization, and backend strategy support. The deterministic evaluator remains the v0 fixture oracle.

The Z3 path now has explicit authorization obligations, query polarity, counterexample translation, and a solver-independent SMT plan. It still needs a high-level obligation-backed evidence adapter and a full Z3 executor.

### External validation

The Action is documented for external smoke testing, but an external integration repository has not yet been run.

### Benchmark depth

The seed benchmark covers pass, fail, and unknown outcomes for the first self-protection path, plus authorization pass and fail cases. It still needs adversarial cases, weak specifications, timeout behavior, unknown solver state, and multi-backend routing.

## Sprint 1 status: closed

Sprint 1 made one PR-style self-protection path work end to end for workflow and verification-control changes.

Exit criterion met: a workflow or `.verification/` change authored by an AI agent produces one of three honest outcomes: allow, block, or require human review. Missing control metadata does not pass.

## Sprint 2 status: mostly complete

Sprint 2 strengthened GitHub metadata ingestion and prepared the OPA-backed self-protection path.

Completed highlights:

- GitHub event parsing.
- GitHub-shaped required-check metadata normalization.
- Conservative branch metadata collector.
- Rego self-protection policy fixture.
- Optional OPA runner.
- OPA evidence normalization.
- Backend strategies: `deterministic`, `opa`, and `both`.
- Optional PR comment posting with update-in-place behavior.
- Installation, branch metadata, strict-mode, and external smoke-test docs.

Remaining Sprint 2 work:

- Run a real external-repository smoke test once an integration repository exists.
- Optionally wire branch metadata collection directly into the Action after token permissions are deliberately configured.
- Expand optional-backend tests when connector safety controls allow direct optional-backend monkeypatching.

## Sprint 3 status: in progress

Sprint 3 focuses on the real Z3 authorization path.

Completed so far:

- Authorization obligation model.
- Explicit query polarity through `find_violation`.
- Obligation serialization for diagnostics and evidence attachment.
- Counterexample translation from obligation witnesses.
- Solver-independent SMT plan and clause representation.
- Tests for obligation construction, serialization, counterexample translation, and SMT plan generation.

Remaining Sprint 3 work:

- Wire the existing authorization adapter through the obligation model.
- Add a Z3 executor that consumes `AuthorizationObligation` or `SmtPlan`.
- Map Z3 `sat`, `unsat`, and `unknown` into OVK evidence.
- Record query polarity and solver model in counterexamples.
- Generate a regression test from an authorization counterexample.
- Add optional integration tests that run only when `z3-solver` is installed.

## Sprint 4: infrastructure exposure path and benchmark hardening

Goal: show the platform and security value of OVK beyond application code.

Deliverables:

- Infrastructure graph abstraction.
- Public sensitive-resource check.
- OPA or graph-backed evaluator.
- Adversarial benchmark cases for missing metadata, unknowns, and vacuity.

## Sprint 5: attestation and release hardening

Goal: make v0 credible externally.

Deliverables:

- Content-addressed evidence statement.
- DSSE-compatible envelope support.
- Optional Sigstore integration.
- Release docs and example repository.
- v0.1 tag preparation.

## Current priority

Sprint 3 is now active. The next priority is to connect the authorization obligation model to an executable Z3-backed path while preserving query polarity and unknown-result discipline.
