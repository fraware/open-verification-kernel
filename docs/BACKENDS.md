# Native Backend Guide

This document describes optional native backend installation for the full OVK ten-backend matrix.

OVK always provides deterministic fallback behavior for portability. When a native backend is available, the native probe tests verify that the runtime outcome remains consistent with the deterministic oracle fixtures.

## Backend Matrix

- `opa` (binary: `opa`)
  - Guarantee class: policy evaluation
  - Install: pinned static release binary (`v0.67.0`)
  - Fixture coverage: `examples/no_agent_self_approval`

- `z3` (binary/import: `z3`)
  - Guarantee class: SMT reachability obligation
  - Install: pinned Python package (`z3-solver==4.13.4.0`)
  - Fixture coverage: `examples/auth_regression`

- `cedar` (binary: `cedar`)
  - Guarantee class: deterministic fallback + optional native binary presence
  - Install: pinned Cargo package (`cedar-policy-cli 4.3.0`)
  - Fixture coverage: `examples/backends/cedar_*.json`

- `tla+` (binary: `tlc`)
  - Guarantee class: deterministic fallback + optional TLC execution environment
  - Install: pinned `tla2tools.jar` (`1.8.0`) with `tlc` wrapper script
  - Fixture coverage: `examples/backends/tla_*.json`

- `kani` (binary: `kani`)
  - Guarantee class: deterministic fallback + optional Rust model checking toolchain
  - Install: pinned Cargo package (`kani-verifier 0.56.0`) plus setup
  - Fixture coverage: `examples/backends/kani_*.json`

- `dafny` (binary: `dafny`)
  - Guarantee class: deterministic fallback + optional Dafny CLI presence
  - Install: pinned GitHub release zip (`4.8.0`)
  - Fixture coverage: `examples/backends/dafny_*.json`

- `verus` (binary: `verus`)
  - Guarantee class: deterministic fallback + optional Verus binary presence
  - Install: pinned git tag install (`0.2024.10.18`)
  - Fixture coverage: `examples/backends/verus_*.json`

- `lean` (binary: `lean`)
  - Guarantee class: deterministic fallback + optional Lean toolchain presence
  - Install: pinned Elan toolchain (`lean4 v4.14.0`)
  - Fixture coverage: `examples/backends/lean_*.json`

- `cbmc` (binary: `cbmc`)
  - Guarantee class: deterministic fallback + optional CBMC binary presence
  - Install: pinned Debian package (`6.4.1`)
  - Fixture coverage: `examples/backends/cbmc_*.json`

- `alloy` (binary: `alloy`)
  - Guarantee class: deterministic fallback + optional Alloy launcher presence
  - Install: pinned Maven jar (`6.2.0`) with CLI wrapper script
  - Fixture coverage: `examples/backends/alloy_*.json`

## Deterministic Fallback Semantics

- External adapters (`cedar`, `tla+`, `kani`, `dafny`, `verus`, `lean`, `cbmc`, `alloy`) use deterministic evaluators as the stable oracle path.
- OPA and Z3 lanes also preserve deterministic behavior via:
  - `ovk.adapters.opa.self_protection.evaluate_self_protection`
  - `ovk.adapters.z3.deterministic_path.evaluate_deterministic_authorization_path`
- Missing native binaries do not block deterministic verification, but native probes assert `used_native_binary=True` when the backend is available.

## CI Entry Points

- Installer script: `scripts/ci/install_backend.sh`
- Matrix workflow: `.github/workflows/native-backends.yml`
- Native tests: `tests/test_native_backends.py`
