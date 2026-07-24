# ADR 0001: Verifier-assurance architecture (OVK-VA-00)

## Status

Accepted. Ordinary CI/MCP/Action surfaces remain frozen as documented below. Assurance runtime (OVK-VA-01…14) is implemented in-tree as an **opt-in** surface and is gated on the PCS pin documented in [PCS_PIN.md](../PCS_PIN.md).

- Development against the sibling/path pin: **OPEN**
- Pin identity (merge-to-main for pin purposes): **SATISFIED** at pcs-core `fb588a41a7eab68064429e3c4dfb26c328b9863d` (see [PCS_PIN.md](../PCS_PIN.md)); install/check out that SHA (do not assume a newer sibling `main` tip); PyPI publish still pending

## Context

OVK is a heterogeneous verification kernel: lane evaluators, optional external backends, an `ovk.cache.v3` result cache, evidence bundles, and in-toto-style attestation. A verifier-assurance programme requires reproducible checker invocation, immutable configuration profiles, evidence packs, replay, typed mutation, and export to portable PCS artifacts — without breaking ordinary CI mode or inventing local PCS schema forks.

Sibling `pcs-core` is the authority for portable assurance schemas. FormalPR-Holdout and private stores remain the authority for hidden labels. PF-Core remains the authority for small machine-checked trace predicates.

## Decision

### Ownership

| Owner | Owns | Does not own |
|---|---|---|
| **OVK** | Checker invocation; configuration snapshots; invocation records; evidence-pack layout and writers; typed mutations; thin mapping from OVK snapshots/records to pinned PCS types; ordinary CI/MCP/Action execution | Portable PCS schemas; hidden-label stores; RL/training; campaign orchestration |
| **PCS (`pcs-core`)** | Portable schemas and conformance fixtures (`VerifierProfile.v1`, `VerificationResult.v1`, and related VA artifact types as PCS names them); Canonical JSON / digest rules; `pcs validate` semantics | Checker binaries; OVK runtime config; hidden labels |
| **PF-Core** | Small machine-checked trace predicates and Lean trust-kernel checks | Campaign stats; OVK lane policy; VA orchestration |
| **FormalPR-Holdout / private stores** | Hidden labels and private adjudication rationale | Public OVK evidence packs |

OVK **pins and validates** PCS schemas. OVK **never forks** PCS schemas into `schemas/` or invents parallel `VerifierProfile` / `VerificationResult` types under an OVK `$id`.

Lean/PF-Core assurance adapters **invoke** PF-Core / Lean; they do not redefine kernel semantics.

OVK imports **only post-freeze adjudication references**. Active or hidden FormalPR-Holdout labels must remain inaccessible to policies and verifiers (see [HOLDOUT_LABEL_SEPARATION.md](../HOLDOUT_LABEL_SEPARATION.md)).

### Explicit exclusions

OVK verifier-assurance does **not** implement or host:

- Reinforcement learning or training loops
- Attack orchestration / red-team campaign runners
- Campaign statistics or optimization-campaign control planes
- Environment simulation frameworks
- A hidden-label database or any store of FormalPR-Holdout ground truth inside OVK

Those concerns belong to other repos or private partner systems. PCS may define portable *record* types for some of them; OVK does not execute those workflows.

### Ordinary CI mode vs assurance mode

| Mode | Entry points | Default? | Contract |
|---|---|---|---|
| **Ordinary CI** | `ovk check`, `ovk verify`, `ovk ci`, GitHub Action (`action.yml`), MCP (`ovk-mcp`) | Yes | Behavior and public schemas frozen per compatibility section below |
| **Assurance** | `ovk verifier …`; adapters that advertise assurance capability fields | No (opt-in) | Requires assurance-capable adapters + PCS pin; missing checker → typed indeterminate |

Existing `deterministic_fallback` external adapters remain **non-assurance**. They must not appear in assurance manifests as replayable PCS emitters. Cedar remains out of the assurance policy tranche (OPA only for policy engines, via `opa-policy`).

### No stubs / placeholders for assurance-capable adapters

An adapter that claims assurance capability must not ship:

- `TODO` / empty `pass` production paths
- Fabricated evidence or mocked production paths labeled as native/assurance
- Silent `deterministic_fallback` results labeled as native or assurance-capable
- Fixtures that bypass the behavior under test

Missing checker → typed indeterminate. Unsupported mutation → explicit failure. If a planned adapter cannot meet the real-checker bar, it does not merge.

### PCS-first gate

OVK-VA-00 (this ADR + baseline) established ownership and the freeze.

**Development gate (OPEN):** OVK-VA-01…14 may be developed and tested against the documented sibling/path pin in [PCS_PIN.md](../PCS_PIN.md) (`OVK_PCS_CORE_PATH` / `PCS_CORE_PATH` / `../pcs-core` / installed `pcs-core`).

**Merge-to-main gate (still required):** OVK-VA-01…14 must not merge to `main` until all of the following are true:

1. `pcs-core` **publishes** (committed, registered, releasable) at least `VerifierProfile.v1`, `VerificationResult.v1`, and authoritative conformance fixtures for those types (plus invocation/replay/mutation artifact schemas as PCS names them).
2. OVK **pins** that published PCS revision (preferred: optional extra `assurance = ["pcs-core==<version>"]` **or** documented git commit pin with schema digests verified in CI — see [PCS_PIN.md](../PCS_PIN.md)).
3. Assurance CI jobs can run PCS fixture validation against OVK-emitted packs; unknown schema versions fail closed.

The merge pin identity is the committed pcs-core SHA `fb588a41a7eab68064429e3c4dfb26c328b9863d` documented in PCS_PIN.md. PyPI remains pending.

### Backward-compatibility freeze

Public contracts that must remain valid through the assurance programme unless a dedicated, versioned migration ADR supersedes this freeze:

**CLI commands** (from `ovk.core.release_metadata.SUPPORTED_COMMANDS`):

- `ovk init`, `ovk check`, `ovk doctor`, `ovk run`, `ovk generate-test`, `ovk repair-suggest`, `ovk ci`
- `ovk auth-obligation`, `ovk infra-exposure`, `ovk ci-secrets`, `ovk deployment-state`
- `ovk release-bundle`, `ovk release-preflight`, `ovk evidence-quality`, `ovk validate-outputs`, `ovk verify`
- `ovk extract-workflow`, `ovk plan`, `ovk infer`, `ovk template list|show|apply`, `ovk bench`, `ovk pilot`

`ovk verifier …` subcommands are additive and must not change the semantics of the list above.

**GitHub Action** (`action.yml`): existing input names and defaults remain stable.

**MCP tools** (`ovk.mcp_server`): existing tool names and payload shapes remain valid for existing callers.

**Schemas that must remain valid** (consumers and CI already validate):

- `verification.evidence.schema.json` / `verification.evidence.v2.schema.json` / `verification.evidence.v3.schema.json`
- `verification.bundle.schema.json` / `verification.bundle.v2.schema.json`
- `verification.capability.schema.json` (assurance sections are **optional**; missing ⇒ ordinary-only)
- `verification.obligation.schema.json`, `backend.routing.schema.json`, `backend.execution.schema.json`
- `verification.result.schema.json`, `verification.intent.schema.json`, `verification.config.schema.json`
- `attestation.statement.schema.json`, `attestation.envelope.schema.json`, `artifact.manifest.schema.json`, `provenance.schema.json`
- `evidence.quality.schema.json`, `preflight.report.schema.json`, lane input schemas

Additive optional fields are allowed when they are backward-compatible. Removing or renaming required fields requires a versioned schema bump and migration note.

### Cache replay vs assurance invocation replay

| Mechanism | Schema / artifact | Purpose | Not |
|---|---|---|---|
| **Ordinary cache replay** | `ovk.cache.v3` / `CachedBackendExecution` | Reuse a prior control-plane attempt under the same content-addressed key | Not a PCS assurance replay; not an evidence pack |
| **Assurance invocation replay** | PCS `VerifierReplayReport.v1` + OVK invocation evidence | Reconstruct checker + immutable config, detect drift, re-execute when deterministic | Not a silent cache hit; fail closed on drift |

These mechanisms must remain distinct in code and docs. A cache hit must never be labeled as assurance replay.

## PCS gate status

Assessed against pcs-core commit `fb588a41a7eab68064429e3c4dfb26c328b9863d` on 2026-07-24 (VA schemas landed via pcs-core PR #26; PyPI not published). OVK pins that SHA explicitly; a newer pcs-core tip may drop or rename pin-surface schemas and must not be treated as this pin:

| Requirement | Status |
|---|---|
| Development / RC pin (`docs/PCS_PIN.md` + optional `assurance` extra) | **CLOSED** on committed SHA `fb588a41a7eab68064429e3c4dfb26c328b9863d` |
| Published (pushed / PyPI) VA schemas | **Pending** — pin is a git commit install; no PyPI release yet |
| Merge-to-main pin identity for VA-01–14 | **Satisfied for pin purposes** at `fb588a41a7eab68064429e3c4dfb26c328b9863d`; distributed consumers still need a PyPI release (or git SHA install) |

**Gate verdict: pin identity CLOSED at the documented SHA; PyPI still PENDING.**

OVK must not vendor or fork PCS schemas. See [PCS_PIN.md](../PCS_PIN.md).

## Implementation map (VA-01…14)

| PR | Deliverable | Location |
|---|---|---|
| VA-01 | Optional assurance capability fields | `schemas/verification.capability.schema.json`, adapters |
| VA-02 | Snapshot + PCS profile export | `ovk/assurance/snapshot.py`, `pcs_export.py` |
| VA-03 | Invocation + evidence packs | `ovk/assurance/invocation.py`, `evidence_pack.py` |
| VA-04 | Replay engine | `ovk/assurance/replay.py` |
| VA-05 | Typed mutation | `ovk/assurance/mutation.py` |
| VA-06…11 | Six assurance backends | `ovk/adapters/assurance/` |
| VA-12 | Conformance harness + examples | `ovk/assurance/conformance.py`, `examples/assurance/` |
| VA-13 | Post-freeze adjudication import | `ovk/assurance/adjudication.py` |
| VA-14 | Docs / non-claims / quality bar | `docs/assurance/`, this ADR, threat model |

## Baseline and inventory pointers

- Durable baseline record: [../baseline/OVK-VA-00-baseline.md](../baseline/OVK-VA-00-baseline.md)
- Adapter / evidence inventory: [../assurance/ADAPTER_INVENTORY.md](../assurance/ADAPTER_INVENTORY.md)
- User guide: [../assurance/GUIDE.md](../assurance/GUIDE.md)

## Pre-existing failures (not repaired in VA-00)

Baseline `pytest` reported 6 failures that do **not** block this documentation ADR. They were **not** repaired in VA-00. Recorded in the baseline artifact for follow-up outside the assurance programme:

- `tests/test_cache_worker_control_plane.py::test_worker_rejects_non_positive_wall_budget`
- `tests/test_runtime_cache_regimes.py` (3 tests)
- `tests/test_trusted_policy_loading.py` (2 tests)

## Consequences

- Ordinary CI remains the default trust surface; assurance is opt-in and PCS-gated.
- Assurance modules live under `ovk/assurance/` and the `verifier` Typer subgroup; they must not alter ordinary `ovk check` / MCP / Action semantics.
- Adapter PRs that claim assurance without a real checker are rejected.
- Programme board tracks PyPI (or equivalent versioned) publish of the pinned pcs-core revision as the remaining distribution step; pin identity for VA-01…14 is the documented SHA in [PCS_PIN.md](../PCS_PIN.md).

## Related

- [PCS_PIN.md](../PCS_PIN.md)
- [ADAPTER_INVENTORY.md](../assurance/ADAPTER_INVENTORY.md)
- [GUIDE.md](../assurance/GUIDE.md)
- [OVK-VA-00-baseline.md](../baseline/OVK-VA-00-baseline.md)
- [BACKENDS.md](../BACKENDS.md)
- [HOLDOUT_LABEL_SEPARATION.md](../HOLDOUT_LABEL_SEPARATION.md)
- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [SCHEMA_INDEX.md](../SCHEMA_INDEX.md)
