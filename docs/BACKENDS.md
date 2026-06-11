# Native Backend Guide

OVK connects to ten formal-methods tools. Every backend has a **built-in fallback** that runs without installing native binaries, so local development and CI stay portable.

When a native binary is installed, OVK can use it and records that fact in evidence. CI verifies that native results match the built-in fallback and that evidence does not falsely claim native execution.

**Important:** a required-in-CI job proves the native install path works and stays consistent with the built-in evaluator. It does not mean every consumer run uses a native binary. Evidence must state which path ran.

## Required in CI (OPA, Z3, CBMC, Cedar)

Workflow: [`.github/workflows/native-backends-tier1.yml`](../.github/workflows/native-backends-tier1.yml) (required native backends; filename is historical)

| Backend | Install | Native execution |
|---------|---------|------------------|
| `opa` | OPA `v0.67.0` static release | Yes |
| `z3` | `z3-solver` Python package `4.13.4.0` | Yes |
| `cbmc` | CBMC Debian `6.4.1` | Yes — native harness execution for all four data-boundary templates |
| `cedar` | `cedar-policy-cli` `4.8.2` | Yes |

Installer: [`scripts/ci/install_backend.sh`](../scripts/ci/install_backend.sh)

Tests: `tests/test_native_backends.py` and per-backend integration tests.

## Optional in CI (informational)

Workflow: [`.github/workflows/native-backends.yml`](../.github/workflows/native-backends.yml) (does not block merges)

Backends: `tla+`, `kani`, `dafny`, `verus`, `lean`, `alloy`

These use built-in evaluators when binaries are missing. Verification still runs; evidence reports whether a native binary was used.

## All backends

| Backend | Binary | Guarantee type | Example fixtures |
|---------|--------|----------------|------------------|
| `opa` | `opa` | Policy evaluation | `examples/no_agent_self_approval` |
| `z3` | `z3-solver` | SMT reachability | `examples/auth_regression` |
| `cedar` | `cedar` | Policy evaluation | `examples/backends/cedar_*.json` |
| `tla+` | `tlc` | State machine | `examples/backends/tla_*.json` |
| `kani` | `kani` | Rust model checking | `examples/backends/kani_*.json` |
| `dafny` | `dafny` | Proof obligations | `examples/backends/dafny_*.json` |
| `verus` | `verus` | Verified Rust | `examples/backends/verus_*.json` |
| `lean` | `lean` | Theorem proving | `examples/backends/lean_*.json` |
| `cbmc` | `cbmc` | Bounded C verification (native harness) | `examples/backends/cbmc_*.json`, `examples/backends/cbmc_harness/*.c` |
| `alloy` | `alloy` | Relational models | `examples/backends/alloy_*.json` |

## Built-in fallback behavior

- External adapters (`cedar`, `tla+`, `kani`, `dafny`, `verus`, `lean`, `cbmc`, `alloy`) always have a built-in evaluator path.
- OPA and Z3 check types also preserve deterministic behavior when native tools are absent.
- Required-in-CI backends must report `used_native_binary=True` only when the native tool actually ran.
- Optional backends must not claim native execution when only the built-in path ran.

## CI entry points

- Installer: `scripts/ci/install_backend.sh`
- Required checkers: `.github/workflows/native-backends-tier1.yml`
- Optional checkers: `.github/workflows/native-backends.yml`
- Tests: `tests/test_native_backends.py`
