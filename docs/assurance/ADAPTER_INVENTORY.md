# OVK adapter and evidence inventory

Inventory of verification adapters, evidence models, and the distinction between ordinary cache replay and assurance invocation replay. Companion to [ADR 0001](../adr/0001-verifier-assurance-architecture.md), the [VA-00 baseline](../baseline/OVK-VA-00-baseline.md), and the [assurance guide](GUIDE.md).

Baseline SHA for the programme start: `e7097351c9a09a2e9f3626fb981f089b14b8cb4d`. Implementation status below reflects the working tree after OVK-VA-01…14.

## Protocols

| Protocol | Location | Role |
|---|---|---|
| `BackendAdapter` | `ovk/adapters/contract.py` | Authoritative control-plane protocol: `manifest → can_handle → compile → fingerprint → run → normalize → explain` |
| `ExternalAdapter` | `ovk/adapters/contract.py` | Legacy wave1/wave2 optional backend surface (dict/legacy dataclasses) |
| `VerificationAdapter` | `ovk/adapters/base.py` | Older protocol alias still present for historical callers |
| `BaseExternalAdapter` | `ovk/adapters/external/base_adapter.py` | Deterministic-fallback skeleton for external backends |

Optional assurance methods (snapshot / run-with-evidence / replay / mutate) live under `ovk/assurance/` and assurance-only adapters in `ovk/adapters/assurance/`. Ordinary adapters remain ordinary unless they advertise a validated assurance section in their capability manifest.

## Registered ordinary `BackendAdapter` instances

Built via lane/domain registry builders in `ovk/adapters/*/__init__.py` and routed from `ovk/core/routing_pipeline.py` / `ovk/core/adapter_runtime.py`.

### Domain / native-or-deterministic backends

| `backend_id` | Class | Registry builder | Execution character |
|---|---|---|---|
| `opa-native` | `OpaNativeSelfProtectionAdapter` | `build_self_protection_registry` | Real `opa eval` when OPA present; self-protection domain |
| `self-protection-deterministic` | `SelfProtectionDeterministicAdapter` | `build_self_protection_registry` | Deterministic policy evaluator |
| `z3-native` | `Z3NativeAuthorizationAdapter` | `build_authorization_registry` | Native Z3 SMT when solver present |
| `authorization-deterministic` | `AuthorizationDeterministicAdapter` | `build_authorization_registry` | Deterministic authorization evaluator |
| `infrastructure-deterministic` | `InfrastructureDeterministicAdapter` | `build_infrastructure_registry` | Deterministic exposure-graph check |
| `ci-secrets-deterministic` | `CiSecretsDeterministicAdapter` | `build_ci_secrets_registry` | Deterministic secrets-boundary check |
| `deployment-deterministic` | `DeploymentDeterministicAdapter` | `build_deployment_registry` | Deterministic approval state machine |

### Lane wrapper backends

| `backend_id` | Class | Registry |
|---|---|---|
| `lane-self-protection` | `SelfProtectionLaneAdapter` | `build_default_lane_registry` |
| `lane-authorization` | `AuthorizationLaneAdapter` | `build_default_lane_registry` |
| `lane-infrastructure` | `InfrastructureLaneAdapter` | `build_default_lane_registry` |
| `lane-ci-secrets` | `CiSecretsLaneAdapter` | `build_default_lane_registry` |
| `lane-deployment` | `DeploymentLaneAdapter` | `build_default_lane_registry` |

Lane wrappers adapt existing evaluators onto `BackendAdapter` for registry use. They are ordinary-mode surfaces, not assurance emitters.

## External / optional backends (`ExternalAdapter`)

Capability manifests live under `adapters/*/capability.json` (packaged with the wheel). Maturity summary matches [BACKENDS.md](../BACKENDS.md).

| Backend name | Adapter class | Native execution today? | Assurance-capable? |
|---|---|---|---|
| `opa` | lane/native path via `opa-native` + OPA helpers | Yes (when `opa` installed) | No — ordinary path; assurance uses `opa-policy` |
| `z3` | `Z3NativeAuthorizationAdapter` / z3 helpers | Yes (when Z3 installed) | No |
| `cbmc` | `CbmcAdapter` | Yes for explicit/template harness | No |
| `cedar` | `CedarAdapter` | No (deterministic + CLI probe) | **No** — excluded from assurance policy tranche |
| `tla+` | `TlaAdapter` | No (deterministic contract) | No |
| `kani` | `KaniAdapter` | No | No |
| `dafny` | `DafnyAdapter` | No | No |
| `verus` | `VerusAdapter` | No | No |
| `lean` | `LeanAdapter` | No (`deterministic_fallback`) | No — assurance uses `lean-pfcore` |
| `alloy` | `AlloyAdapter` | No | No |

**Rule (ADR 0001):** `deterministic_fallback` adapters stay non-assurance. No stub assurance adapters.

## Assurance-capable backends (opt-in)

Registered only for the verifier registry (`ovk/assurance/registry.py`), not ordinary lane routing. See [GUIDE.md](GUIDE.md).

| `backend_id` | Module | VA | Guarantee class | Missing tool |
|---|---|---|---|---|
| `auth-state-predicate` | `ovk/adapters/assurance/auth_state.py` | VA-06 | observational | n/a (pure predicate) |
| `pytest-suite` | `ovk/adapters/assurance/pytest_suite.py` | VA-07 | runtime_observed | typed indeterminate |
| `opa-policy` | `ovk/adapters/assurance/opa_policy.py` | VA-08 | certificate_checked | typed indeterminate |
| `lean-pfcore` | `ovk/adapters/assurance/lean_pfcore.py` | VA-09 | formally_checked | typed indeterminate |
| `sql-state-diff` | `ovk/adapters/assurance/sql_diff.py` | VA-10 | observational | n/a (SQLite stdlib) |
| `model-judge` | `ovk/adapters/assurance/model_judge.py` | VA-11 | empirically_measured | CI contract fake; stochastic |

## Evidence and execution models

| Model | Location | Schema / version | Role |
|---|---|---|---|
| `VerificationEvidence` | `ovk/core/models.py` | `ovk.evidence.v1` (+ v2 preview fields) | Per-lane / per-intent evidence |
| `EvidenceBundle` | `ovk/core/models.py` | `ovk.bundle.v1` | Aggregate decision + evidence list |
| Evidence v2/v3 JSON Schema | `schemas/verification.evidence.v2.schema.json`, `…v3…` | schema files | Control-plane enriched evidence |
| Bundle v2 JSON Schema | `schemas/verification.bundle.v2.schema.json` | schema file | Bundles of v2 evidence |
| `RawBackendExecution` | `ovk/core/execution_models.py` | `backend.execution.schema.json` | Raw checker attempt |
| `NormalizedBackendResult` | `ovk/core/execution_models.py` | same | Normalized status / guarantee / counterexamples |
| `CachedBackendExecution` | `ovk/core/execution_models.py` | **`ovk.cache.v3`** | Provenance-preserving cache payload |
| `ObligationExecutionRecord` | `ovk/core/execution_models.py` | backend execution schema | Full compile/route/execute record |
| `BackendCapabilityManifest` | `ovk/core/execution_models.py` | `verification.capability.schema.json` | Adapter capability declaration (optional assurance sections) |
| `BackendEnvironmentFingerprint` | `ovk/core/execution_models.py` | execution models | Thin env fingerprint (ordinary); assurance uses richer snapshots |
| Release attestation | `ovk/core/attestation.py`, `release_bundle.py` | attestation schemas | in-toto-style release artifacts |
| Evidence quality / invariants | `ovk/core/evidence_invariants.py` | quality / invariant schemas | Post-run quality reporting |

### Assurance artifacts (OVK runtime → PCS export)

| Artifact | OVK module | PCS type / packing |
|---|---|---|
| Configuration snapshot / profile | `ovk/assurance/snapshot.py`, `pcs_export.py` | PCS `VerifierProfile.v1` → `verifier_profile.pcs.json` |
| Verification result | `ovk/assurance/pcs_export.py` | PCS `VerificationResult.v1` → `verification_result.pcs.json` |
| Invocation record | `ovk/assurance/invocation.py`, `evidence_pack.py` | PCS `VerifierInvocationRecord.v1` → `invocation.json` |
| Evidence pack layout | `ovk/assurance/evidence_pack.py` | OVK-local dirs/sidecars (`raw/`, `normalized/`, `provenance/`, `compiled_obligation.json`) |
| Replay report | `ovk/assurance/replay.py` | PCS `VerifierReplayReport.v1` → `replay_report.pcs.json` |
| Mutation manifest | `ovk/assurance/mutation.py` | PCS `VerifierMutationManifest.v1` |

Opaque `invocation_ref` on results carries `invocation_id` + `invocation_digest` only. PCS schemas are **never** forked under OVK `schemas/`. Authoritative type set and digests: [PCS_PIN.md](../PCS_PIN.md) / `ovk.assurance.pin`.

## Cache replay vs assurance invocation replay

### Ordinary: `ovk.cache.v3` cache replay

- Implemented in `ovk/core/result_cache.py` (`CACHE_SCHEMA_VERSION = "ovk.cache.v3"`).
- Payload type: `CachedBackendExecution`.
- Purpose: content-addressed reuse of a prior backend attempt under matching key components.
- Scope: ordinary control-plane / CI performance and provenance continuity.
- **Not** a PCS assurance replay and **not** an evidence pack.

### Assurance: invocation replay (OVK-VA-04)

- Validates an invocation record, reconstructs checker + immutable configuration, detects missing deps / config drift, re-executes when deterministic, compares digests, emits a PCS replay report.
- Stochastic backends must preserve nondeterminism declarations rather than fake bit-identical replay.
- Drift fails closed.
- Entry point: `ovk verifier replay …`.

**Invariant:** labeling a cache hit as assurance replay is forbidden.

## Surfaces

| Surface | Entry | Mode |
|---|---|---|
| CLI | `ovk check`, `ovk verify`, lane commands | Ordinary (default) |
| GitHub Action | `action.yml` | Ordinary |
| MCP | `ovk-mcp` / `ovk.mcp_server` | Ordinary |
| Release | `ovk release-bundle`, `ovk validate-outputs` | Ordinary |
| Assurance CLI | `ovk verifier describe\|snapshot-config\|run\|replay\|mutate\|validate-evidence` | Assurance (opt-in) |
| Conformance | `ovk.assurance.conformance` / `tests/assurance/` | Assurance |
| Adjudication import | `ovk.assurance.adjudication` | Assurance (post-freeze only) |

## Related

- [GUIDE.md](GUIDE.md)
- [ADR 0001](../adr/0001-verifier-assurance-architecture.md)
- [BACKENDS.md](../BACKENDS.md)
- [ADAPTER_CONTRACT.md](../ADAPTER_CONTRACT.md)
- [SCHEMA_INDEX.md](../SCHEMA_INDEX.md)
- [ARTIFACTS.md](../ARTIFACTS.md)
- [PCS_PIN.md](../PCS_PIN.md)
