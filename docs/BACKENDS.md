# Backend Execution Guide

OVK exposes a common evidence contract across ten formal-methods backends. Their execution depth is not uniform. This document is the authoritative statement of what each backend actually executes in v1.2.0 RC.

## Execution maturity

| Backend | Current execution | Native result can determine evidence? | Current limit |
|---|---|---:|---|
| `opa` | Native `opa eval` path plus deterministic self-protection evaluator | Yes, when the OPA strategy is selected | Generic kernel router selections do not yet control lane execution |
| `z3` | Native Python Z3 SMT query plus deterministic authorization evaluator | Yes, when Z3 is installed | The query checks a normalized authorization abstraction, not arbitrary application code |
| `cbmc` | Native bounded checking of an explicit or OVK template harness | Yes | Template/generated harnesses model a risk pattern and do not prove that changed project source was compiled into the model |
| `cedar` | Deterministic Cedar-shaped input evaluator; Cedar CLI version probe | No | Native Cedar policy evaluation is not implemented |
| `tla+` | Deterministic state-machine contract evaluator | No | TLC execution is not implemented |
| `kani` | Deterministic Rust-harness contract evaluator | No | Native Kani execution is not implemented |
| `dafny` | Deterministic proof-obligation contract evaluator | No | Native Dafny verification is not implemented |
| `verus` | Deterministic verified-Rust contract evaluator | No | Native Verus verification is not implemented |
| `lean` | Deterministic theorem-obligation contract evaluator | No | Native Lean checking is not implemented |
| `alloy` | Deterministic relational-model contract evaluator | No | Native Alloy analysis is not implemented |

A binary-presence or version probe is never labeled as native verification. Evidence artifacts record `used_native_binary`, the guarantee type, assumptions, and limits.

## CI tiers

### Native execution required

The Tier 1 workflow requires real execution for:

- OPA policy evaluation;
- Z3 SMT evaluation;
- CBMC bounded harness evaluation.

Workflow: [`.github/workflows/native-backends-tier1.yml`](../.github/workflows/native-backends-tier1.yml).

### Toolchain probe required

Cedar remains in the Tier 1 installation matrix because the CLI/toolchain is installed and version-probed. Its decision remains deterministic and its evidence reports `used_native_binary: false` until policy execution is implemented.

### Informational adapters

TLA+, Kani, Dafny, Verus, Lean, and Alloy remain non-blocking integration surfaces. Their deterministic contract evaluators are useful for schema, routing, and evidence interoperability tests, but they are not native proof execution.

## Fallback rules

- Missing OPA or Z3 cannot fabricate a native pass; the selected path returns a deterministic result or an explicit unknown.
- A CBMC timeout or execution error returns `unknown` or `error` and requires human review. It never falls back to a deterministic pass after native execution was attempted.
- Deterministic external-adapter results use guarantee type `deterministic_fallback`.
- Synthetic CBMC harnesses use guarantee type `template_harness_model_check` and state that changed project source was not compiled into the checked model.
- Only an explicitly supplied CBMC harness can use guarantee type `bounded_model_checking`.

## Capability manifests and routing

Capability manifests live under `adapters/*/capability.json` and are packaged with the wheel. They support intent/backend ranking and MCP capability discovery.

In v1.2.0 RC, router output is advisory metadata. Core lane obligations still execute their lane evaluator, and the selected generic backend does not yet control compilation or execution. Evidence records `routing_enforced: false` until the backend-selection control plane is implemented.

## Entry points

- Installer: `scripts/ci/install_backend.sh`
- Required/probed matrix: `.github/workflows/native-backends-tier1.yml`
- Informational matrix: `.github/workflows/native-backends.yml`
- Probe aggregation: `ovk/core/native_backend_probe.py`
- Integration tests: `tests/test_native_backends.py` and backend-specific test files
