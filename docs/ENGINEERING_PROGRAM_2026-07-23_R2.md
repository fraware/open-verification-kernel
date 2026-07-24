# OVK Engineering Program R2 — 2026-07-23

Execution program derived from [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md). Release positioning: future **`v1.3.0-rc.1`** candidate. Do not re-validate signed `v1.2.1` (`a27d572…`) as if it included the typed control plane.

## Mandatory constraints

- Do not merge trust-chain PRs out of order (identity → cache → contracts → single route → isolation → evidence).
- Every PR must include the eight analysis sections below and fail-closed adversarial tests.
- Sprints 6–7 may overlap late PRs only after PR6 lands.
- External consumer and holdout work needing write access outside this repo is coordinated separately; this repo carries pins, checklists, and scaffolding.

## Per-PR analysis checklist (required)

Every PR in this program must document:

1. **Architecture** — what trust boundary or control-plane invariant changes.
2. **Schema** — which schemas/versions bump and why.
3. **Cache** — key/value identity impact; invalidation or migration.
4. **Migration** — how old artifacts/entries fail closed or upgrade.
5. **Trust-boundary** — what an adversary can no longer forge or confuse.
6. **Adversarial tests** — explicit negative tests that fail closed.
7. **Artifacts** — which evidence/provenance/attestation/release fields change.
8. **Docs** — status, roadmap, and operator-facing honesty updates.

## Sprint 0 — Current-source baseline

On one **non-`[skip ci]`** source SHA, run and retain:

- general CI, native Tier 1, package/wheel smoke outside checkout;
- Action dogfood, release preflight, expanded FormalPR-Bench;
- template conformance, adversarial release-bundle checks.

Record exact workflow run URLs in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).

Introduce `benchmark_source_sha` alongside `verified_source_sha` in badge/summary renderers and schemas. `verified_source_sha` requires a complete observed required-workflow set; badge-only commits must not be labeled verified.

## Sprint 1 — Attempt identity and cache provenance

### PR1 — Deterministic attempt identity

**Targets:** `ovk/core/execution_models.py` (`attempt_digest_input` / `compute_attempt_id`)

**Acceptance:**

- Remove `duration_ms` (and any other timing) from canonical attempt identity; keep duration as observational metadata only.
- Prove stable IDs across sequential, parallel, cached, and uncached equivalent runs.
- Remove/replace vacuous tests that assert timing participates in identity.

### PR2 — Provenance-preserving cache v3

**Targets:** `ovk/core/result_cache.py`, `ovk/core/backend_control_plane.py` cache-hit branch

**Acceptance:**

- Introduce `CachedBackendExecution` storing original `ExecutionAttempt`, `native_execution`, tool version/digest, termination/exit code, raw-result digest, environment fingerprint, normalized result.
- On hit: **replay** stored attempt (do not synthesize; do not re-infer `native_execution` from current tool availability).
- Bump schema to `ovk.cache.v3`; migrate or invalidate v2 entries explicitly.
- Adversarial tests: install/remove native tool between write and hit; prove provenance unchanged.

## Sprint 2 — Routing-contract enforcement

### PR3 — Coverage and guarantee enforcement

**Targets:** `ovk/core/router.py`, `ovk/core/backend_control_plane.py`

**Acceptance:**

- Reject candidates with `coverage_requirements_met=False` as required primaries; allow only as optional corroborators under explicit policy.
- Stop hardcoding `coverage_requirements_met=True` in `_manifest_assessment`.
- On compiler vs router `expected_guarantee` mismatch: compiler-contract error, skip execution, require review — never silent rewrite.

### PR4 — Fallback policy v2

**Targets:** `ovk/core/execution_models.py` (`FallbackPolicy`), `ovk/core/backend_aggregation.py`, evidence decision fields for INV-017

**Acceptance:**

- Replace broad `fallback_accepted=allow_fallback` with backend-, guarantee-, and cause-specific policy.
- Native timeout, tool error, invalid output, and resource exhaustion must never become passing fallback results.

### PR5 — Self-protection trust provenance

**Targets:** `ovk/core/adapter_runtime.py`, `ovk/core/self_protection_compiler.py`

**Acceptance:**

- Default `metadata_trusted=False`.
- Trust only from protected base-workflow provenance, signed service, or explicit maintainer-supplied material.
- Current-state-only branch protection cannot set trusted.

## Sprint 3 — One authoritative route

### PR6 — Single authoritative routing pipeline

**Targets:** `ovk/core/router.py`, kernel/CLI/MCP planning surfaces, evidence/provenance/attestation emitters

**Acceptance:**

- Compile typed obligations **before** routing; route each obligation exactly once; execute that immutable `RoutingDecision`.
- Eliminate dual outcomes from `route_intent` (compat) vs `route_obligation` (typed).
- Same `routing_id` across kernel, CLI, MCP, evidence, provenance, attestation.

## Sprint 4 — Hard adapter isolation

### PR7 — Isolated deterministic workers

**Targets:** five `*DeterministicAdapter.run` classes; `ovk/core/execution_budget.py`

**Acceptance:**

- Move deterministic evaluators behind subprocess/spawned-worker boundary with wall-time, output, env, path, and hard cancellation.
- Control plane always passes worker; in-process-only authoritative adapters are forbidden.

### PR8 — Remaining adapter isolation

**Acceptance:**

- Native OPA/Z3/CBMC/Cedar paths share the same externally enforced worker contract.
- No authoritative adapter may inspect elapsed time only after returning.

## Sprint 5 — Evidence v3 and material binding

### PR9 — Evidence v3 and material-set binding

**Targets:** evidence schema v3, `ovk/core/evidence_invariants.py`, provenance/attestation/release verification

**Acceptance:**

- Require full control-plane trace: compiler, materials, coverage, requested/eligible/attempted backends, execution attempts, routing-enforced state.
- Cross-bind one canonical **material-set digest** across obligation, evidence, provenance, attestation, and release verification; recompute identities during validation.

## Sprint 6 — Source-profile hardening

AST/module-graph authorization profiles; recursive Terraform plans; controller-aware K8s reachability; deeper Actions permissions/secret flow; deployment strictness only on explicit trusted profiles. Touch lane compilers under `ovk/core/*_compiler.py` and source-profile modules.

Parallelizable after PR6.

## Sprint 7 / PR10 — Semantic template conformance v2

Replace file-existence `strict_eligible` generation with:

`catalog_only` | `executable_advisory` | `source_profile_strict_eligible` | `externally_calibrated_strict` | `deprecated`

Every status must derive from executed semantic evidence, not repo-link/fixture/test-file presence.

## Sprint 8 — Label-separated holdout

Generate predictions from the exact RC artifact **without** labels; sign/digest; evaluate separately with protected labels; publish aggregates only. Builds on Phase A holdout hardening.

## Sprint 9 — Consumer validation on current code

Update both consumers from `v1.2.1` to immutable `v1.3.0-rc.1` (or audited commit):

- https://github.com/fraware/ovk-consumer-fastapi-terraform
- https://github.com/fraware/ovk-consumer-express-actions

Dispatch workflows, download evidence, verify bundles, exercise true cross-fork PRs; keep human pilot ledgers separate from automated fixtures. Update [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) pins in this repo; consumer repo PRs require write access.

## Sprint 10 — Attributable publication

- Correct benchmark vs verified-source terminology in published artifacts.
- Require all automated release gates on the exact tag source.
- Sign artifacts; retain workflow IDs and digests.
- Promote to `v1.3.0` only after P0 closure (PRs 1–9), consumer validation, and attributable holdout aggregates.

## Required PR order (summary)

1. Deterministic attempt identity
2. Provenance-preserving cache v3
3. Coverage and guarantee enforcement
4. Fallback policy v2
5. Self-protection trust provenance
6. Single authoritative routing pipeline
7. Isolated deterministic workers
8. Remaining adapter isolation
9. Evidence v3 and material-set binding
10. Template conformance v2

## Phase A prerequisite (before Sprint 0 measurement)

Author this document and the deep audit; rewrite [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) for `v1.3.0-rc.1`; land CI-secrets `size_bytes`, worker env allowlist + zero-budget reject, and FormalPR-Holdout isolation hotfixes.
