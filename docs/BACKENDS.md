# Backend Execution Guide

OVK exposes a common evidence contract across ten formal-methods backends. Their execution depth is not uniform. This document is the authoritative statement of what each backend actually executes for package `1.3.0-rc.1` (engineering candidate).

## Execution maturity

<!-- BEGIN OVK_CAPABILITY_TABLE -->
| Backend | release_status | Current execution | Native result can determine evidence? | Current limit |
|---|---|---|---:|---|
| `opa` | preview | Native path available (tool_dependent) | Yes | Does not prove properties of arbitrary program execution |
| `z3` | preview | Native path available (tool_dependent) | Yes | Does not prove properties outside the encoded abstraction |
| `cbmc` | preview | Native path available (tool_dependent) | Yes | Bounded verification only |
| `cedar` | experimental | Deterministic contract evaluator only (deterministic) | No | Native Cedar policy evaluation is not implemented |
| `tla+` | experimental | Deterministic contract evaluator only (deterministic) | No | TLC execution is not implemented |
| `kani` | experimental | Deterministic contract evaluator only (deterministic) | No | Native Kani execution is not implemented |
| `dafny` | experimental | Deterministic contract evaluator only (deterministic) | No | Native Dafny verification is not implemented |
| `verus` | experimental | Deterministic contract evaluator only (deterministic) | No | Native Verus verification is not implemented |
| `lean` | experimental | Deterministic contract evaluator only (deterministic) | No | Native Lean checking is not implemented |
| `alloy` | experimental | Deterministic contract evaluator only (deterministic) | No | Native Alloy analysis is not implemented |
| `lane-authorization` | experimental | Deterministic contract evaluator only (tool_dependent) | No | Does not reconstruct frameworks beyond the supplied route abstraction. |
| `lane-ci-secrets` | experimental | Deterministic contract evaluator only (deterministic) | No | Does not analyze composite actions beyond the supplied steps. |
| `lane-deployment` | experimental | Deterministic contract evaluator only (deterministic) | No | Does not prove runtime orchestrator behavior beyond the abstraction. |
| `lane-infrastructure` | experimental | Deterministic contract evaluator only (deterministic) | No | Does not prove runtime cloud configurations beyond the abstraction. |
| `lane-self-protection` | experimental | Deterministic contract evaluator only (deterministic) | No | Does not analyze checks outside the declared OVK gate name. |
<!-- END OVK_CAPABILITY_TABLE -->

A binary-presence or version probe is never labeled as native verification. Evidence artifacts record `used_native_binary`, the guarantee type, assumptions, and limits. Tables above are regenerated from `adapters/*/capability.json` via `scripts/render_capability_tables.py`.

## Adapter conformance (OVK-05)

Every advertised adapter ships a seven-item suite under `adapters/<id>/conformance/`:

1. pass fixture
2. fail fixture
3. malformed-output fixture
4. timeout fixture
5. unavailable-binary fixture
6. documentation of what a pass establishes
7. documentation of what remains outside the claim

Validate with `python scripts/validate_adapter_conformance.py`. `release_status=stable` requires all seven; non-conformant adapters that claim `stable` are auto-downgraded when capability tables are rendered. Only native candidates (`opa`, `z3`, `cbmc`) may become `stable` once fully conformant; other adapters remain `preview`/`experimental`.

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
- **Strict post-execution fallback is disabled by default.** Set `routing.allow_fallback: true` in `.verification/config.yml` only when you intentionally accept constrained fallback rules; native timeout, tool error, invalid output, and resource exhaustion still must not become passing results. See [POLICY.md](POLICY.md).

## Capability manifests and routing

Capability manifests live under `adapters/*/capability.json` and are packaged with the wheel. They support intent/backend ranking and MCP capability discovery.

The typed backend control plane (`BackendControlPlane` / `route_obligation`) can enforce lane routing when policy opts in. Default product path remains conservative: evidence still records whether routing was enforced for that run. Generic experimental adapters do not claim native proof execution.

## Entry points

- Installer: `scripts/ci/install_backend.sh`
- Required/probed matrix: `.github/workflows/native-backends-tier1.yml`
- Informational matrix: `.github/workflows/native-backends.yml`
- Probe aggregation: `ovk/core/native_backend_probe.py`
- Integration tests: `tests/test_native_backends.py` and backend-specific test files
