# Native Backend Guide

This document describes optional native backend installation for the full OVK ten-backend matrix.

OVK always provides deterministic fallback behavior for portability. When a native backend is available, tier-1 probes verify that runtime outcomes stay consistent with deterministic oracle fixtures and that evidence does not falsely claim native execution.

## Tier 1 (required in CI)

Blocking workflow: [`.github/workflows/native-backends-tier1.yml`](../.github/workflows/native-backends-tier1.yml)

| Backend | Binary / package | Pinned install | Native execution in OVK |
|---------|------------------|----------------|------------------------|
| `opa` | `opa` | `v0.67.0` static release | Yes — `run_opa_policy` |
| `z3` | `z3-solver` (Python) | `4.13.4.0` | Yes — `run_authorization_obligation_with_z3` |
| `cbmc` | `cbmc` | Debian `6.4.1` | Contract + deterministic oracle today; native CBMC invocation is future work |
| `cedar` | `cedar` | `cedar-policy-cli` `4.8.2` | Yes — `probe_cedar_binary` contract probe with oracle cross-check |

Installer: [`scripts/ci/install_backend.sh`](../scripts/ci/install_backend.sh) runs post-install `which` checks and version assertions for all tier-1 backends.

Tests:

- Matrix probe: `tests/test_native_backends.py`
- Per-backend integration: `tests/test_opa_optional_integration.py`, `tests/test_z3_native_integration.py`, `tests/test_cbmc_native_integration.py`, `tests/test_cedar_native_integration.py`

Evidence honesty: `ovk/core/evidence_invariants.py` rejects `native_tool` claims when deterministic-oracle assumptions are present.

## Tier 2 (informational in CI)

Scheduled / manual workflow: [`.github/workflows/native-backends.yml`](../.github/workflows/native-backends.yml) (`continue-on-error: true`)

Backends: `tla+`, `kani`, `dafny`, `verus`, `lean`, `alloy`

These adapters use deterministic evaluators as the stable oracle path. Missing native binaries do not block verification; probes report `used_native_binary=False` unless a native runner exists.

## Backend Matrix

- `opa` (binary: `opa`)
  - Guarantee class: policy evaluation
  - Fixture coverage: `examples/no_agent_self_approval`

- `z3` (binary/import: `z3`)
  - Guarantee class: SMT reachability obligation
  - Fixture coverage: `examples/auth_regression`

- `cedar` (binary: `cedar`)
  - Guarantee class: deterministic fallback + native contract probe when installed
  - Fixture coverage: `examples/backends/cedar_*.json`

- `tla+` (binary: `tlc`)
  - Guarantee class: deterministic fallback + optional TLC execution environment
  - Fixture coverage: `examples/backends/tla_*.json`

- `kani` (binary: `kani`)
  - Guarantee class: deterministic fallback + optional Rust model checking toolchain
  - Fixture coverage: `examples/backends/kani_*.json`

- `dafny` (binary: `dafny`)
  - Guarantee class: deterministic fallback + optional Dafny CLI presence
  - Fixture coverage: `examples/backends/dafny_*.json`

- `verus` (binary: `verus`)
  - Guarantee class: deterministic fallback + optional Verus binary presence
  - Fixture coverage: `examples/backends/verus_*.json`

- `lean` (binary: `lean`)
  - Guarantee class: deterministic fallback + optional Lean toolchain presence
  - Fixture coverage: `examples/backends/lean_*.json`

- `cbmc` (binary: `cbmc`)
  - Guarantee class: deterministic fallback + optional CBMC binary presence
  - Fixture coverage: `examples/backends/cbmc_*.json`

- `alloy` (binary: `alloy`)
  - Guarantee class: deterministic fallback + optional Alloy launcher presence
  - Fixture coverage: `examples/backends/alloy_*.json`

## Deterministic Fallback Semantics

- External adapters (`cedar`, `tla+`, `kani`, `dafny`, `verus`, `lean`, `cbmc`, `alloy`) use deterministic evaluators as the stable oracle path.
- OPA and Z3 lanes also preserve deterministic behavior via:
  - `ovk.adapters.opa.self_protection.evaluate_self_protection`
  - `ovk.adapters.z3.deterministic_path.evaluate_deterministic_authorization_path`
- Tier-1 probes assert `used_native_binary=True` for OPA, Z3, and Cedar when the backend is available. CBMC uses contract probing without full native harness execution. Tier-2 backends must not claim native execution while using the oracle alone.

## CI Entry Points

- Installer script: `scripts/ci/install_backend.sh`
- Tier 1 (blocking): `.github/workflows/native-backends-tier1.yml`
- Tier 2 (informational): `.github/workflows/native-backends.yml`
- Native tests: `tests/test_native_backends.py`
