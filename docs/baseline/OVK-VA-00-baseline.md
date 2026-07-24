# OVK-VA-00 baseline record

Durable baseline for the OVK verifier-assurance programme, recorded with [ADR 0001](../adr/0001-verifier-assurance-architecture.md).

## Repository pin

| Field | Value |
|---|---|
| Repository | `open-verification-kernel` |
| HEAD commit SHA | `e7097351c9a09a2e9f3626fb981f089b14b8cb4d` |
| HEAD subject | `chore: update FormalPR-Bench badge [skip ci]` |
| Recorded (UTC) | `2026-07-24T16:54:55Z` |
| Host platform | `Windows-11-10.0.26200-SP0` |

## Toolchain versions

| Tool | Version | Notes |
|---|---|---|
| Python | 3.13.11 | Local Windows Python used for the baseline measurement |
| ruff | 0.11.2 | from `ruff --version` / `importlib.metadata` |
| pytest | 8.3.5 | from `pytest --version` |
| open-verification-kernel (installed) | 1.2.1 | editable install of this workspace for CLI smoke |

## Commands run

### 1. `pytest` (full suite)

```text
pytest -q --tb=no
```

| Metric | Result |
|---|---|
| Passed | 673 |
| Failed | 6 |
| Skipped | 22 |
| Warnings | 12 (deprecation / pytest-asyncio config) |
| Duration | ~167 s |
| Exit code | **1** (failures present) |

Failed tests (pre-existing; **not repaired** in VA-00 — they do not block this documentation ADR):

1. `tests/test_cache_worker_control_plane.py::test_worker_rejects_non_positive_wall_budget`
2. `tests/test_runtime_cache_regimes.py::test_enforced_execution_does_not_reuse_legacy_flat_cache`
3. `tests/test_runtime_cache_regimes.py::test_enforced_evidence_has_only_authoritative_typed_routing`
4. `tests/test_runtime_cache_regimes.py::test_shadow_mode_uses_only_control_plane_namespace_cache`
5. `tests/test_trusted_policy_loading.py::test_changed_policy_is_loaded_from_base_revision`
6. `tests/test_trusted_policy_loading.py::test_changed_policy_without_base_material_uses_safe_builtin`

Honest summary: the suite is **not fully green** at this baseline SHA. Core ordinary paths exercised by the majority of tests pass; the six failures cluster on cache-regime/worker-budget and trusted-policy loading behavior.

### 2. `ovk doctor`

```text
ovk doctor
```

| Metric | Result |
|---|---|
| Overall `passed` | **false** |
| Exit code | **1** |

Core / packaging checks that passed:

- `ovk_version` → `1.2.1`
- `python` → `Python 3.13.11`
- `example_manifest` → 5 lanes in example manifest
- `template_library` → 100 intent templates
- `schema_resources` → core packaged schemas present
- `lean` → present on PATH (`elan`)
- `github_token` → optional locally
- `platform` → recorded
- `verification_config_schema` → config absent (optional OK)

Checks that failed (expected on a fresh checkout without optional toolchains / `.verification/`):

- Optional native tools missing from PATH: `opa`, `z3`, `cedar`, `tlc`, `kani`, `dafny`, `verus`, `cbmc`, `alloy`, `cosign`
- `verification_dir` → `.verification` missing

Doctor failure here is an environment layout / optional-toolchain signal, not a kernel regression by itself.

### 3. `ovk check` smoke

```text
ovk check \
  --changed-files examples/multi_surface/pr_combined.diff \
  --output-dir .ovk-va00-check \
  --advisory
```

| Metric | Result |
|---|---|
| Exit code | **0** (advisory) |
| Merge recommendation | `block` (expected for the multi-surface failing fixture) |
| Lanes exercised | self-protection (`opa`, pass), ci_secrets (fail), authorization/`z3` path (fail), infrastructure (fail) |
| Artifacts written | `ovk-evidence.json`, `ovk-pr-comment.md`, `ovk-attestation.json`, `ovk-artifact-manifest.json`, `ovk-evidence-quality.json`, `ovk-attestation-envelope.json` |

Smoke verdict: **pass** (command succeeded and wrote the standard artifact set).

## PCS gate snapshot (external)

Historical assessment at VA-00 recording time used a pre-pin draft checkout. **Do not treat the historical table below as current.** Authoritative current pin: [PCS_PIN.md](../PCS_PIN.md) (`fb588a41a7eab68064429e3c4dfb26c328b9863d`).

| Artifact | At VA-00 recording | Current (addendum) |
|---|---|---|
| `VerifierProfile.v1` | Draft / unpublished | Present at pinned SHA |
| `VerificationResult.v1` | Draft / unpublished | Present at pinned SHA |
| Invocation / replay / mutation VA schemas | Draft / unpublished | Present at pinned SHA (required by `ovk.assurance.pin`) |
| OVK pin document | Development | [PCS_PIN.md](../PCS_PIN.md); optional `assurance` extra |

**PCS gate (current): pin `fb588a41a7eab68064429e3c4dfb26c328b9863d` CLOSED for pin identity; PyPI PENDING.** Sibling `../pcs-core` on a newer tip may drift; always resolve the documented SHA. See ADR 0001.

## Addendum — programme progress (not part of the VA-00 measurement)

This baseline remains a historical record of the programme start SHA and command results. It is not rewritten when later PRs land.

As of 2026-07-24 (pin retarget):

| Item | Status |
|---|---|
| OVK-VA-01–14 implementation | Present under `ovk/assurance/`, `ovk/adapters/assurance/`, `tests/assurance/`, `examples/assurance/`, `docs/assurance/` |
| Ordinary surfaces | Unchanged; see ADR compatibility freeze |
| pcs-core pin | **Committed** SHA `fb588a41a7eab68064429e3c4dfb26c328b9863d` — see [PCS_PIN.md](../PCS_PIN.md); PyPI pending |
| Merge to `main` | **Pin identity satisfied** for pin purposes; PyPI still pending for versioned installs (git SHA install works) |


Authoritative current docs: [assurance/GUIDE.md](../assurance/GUIDE.md), [assurance/ADAPTER_INVENTORY.md](../assurance/ADAPTER_INVENTORY.md), [CHANGELOG_VERIFIER_ASSURANCE.md](../CHANGELOG_VERIFIER_ASSURANCE.md).

## Related

- [ADR 0001 — Verifier-assurance architecture](../adr/0001-verifier-assurance-architecture.md)
- [Adapter inventory](../assurance/ADAPTER_INVENTORY.md)
- [Assurance guide](../assurance/GUIDE.md)
