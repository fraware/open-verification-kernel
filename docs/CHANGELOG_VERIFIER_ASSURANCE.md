# Verifier-assurance changelog (OVK-VA-00…14)

## Unreleased — verifier-assurance programme

### Added

- **VA-00:** ADR, baseline, adapter inventory, ordinary-vs-assurance freeze, PCS development pin.
- **VA-01…05:** Optional assurance capability manifests, configuration snapshots, invocation/evidence packs, replay, typed mutations, `ovk verifier` CLI.
- **VA-06:** `auth-state-predicate` — exact predicates over declared authoritative state materials.
- **VA-07:** `pytest-suite` — real pytest runner; `runtime_observed` only.
- **VA-08:** `opa-policy` — assurance-capable real `opa eval` (missing opa → indeterminate). Cedar excluded.
- **VA-09:** `lean-pfcore` — real Lean/PF-Core surface; ordinary Lean `deterministic_fallback` remains non-assurance.
- **VA-10:** `sql-state-diff` — SQLite offline before/after digests.
- **VA-11:** `model-judge` — stochastic empirical judge with CI contract fake; cannot upgrade guarantee class.
- **VA-12:** Cross-adapter 14-test conformance harness + `examples/assurance/` packs.
- **VA-13:** Post-freeze adjudication importer with label isolation and audit events.
- **VA-14:** Assurance guide, non-claims, threat-model / BACKENDS / ARCHITECTURE / adapter-contract notes, schema-index PCS pointer.
- Aligned pin/docs/exporters with pcs-core OVK pin surface: `VerifierProfile.v1`, `VerificationResult.v1`, `VerifierInvocationRecord.v1`, `VerifierReplayReport.v1`, `VerifierMutationManifest.v1` at commit `fb588a41a7eab68064429e3c4dfb26c328b9863d`.
- Assurance CI job (`tests/assurance` + PCS conformance + pin digest verify).
- Adversarial secret redaction (value patterns, list recursion) and fail-closed timeout/missing-checker split in VA-12.

### Compatibility

- Ordinary `ovk check`, MCP, and GitHub Action contracts unchanged.
- Pin identity for merge-to-main is **satisfied** at the documented pcs-core SHA ([PCS_PIN.md](PCS_PIN.md)). PyPI publish of pcs-core remains pending.

### Non-claims

See [assurance/GUIDE.md](assurance/GUIDE.md#non-claims).
