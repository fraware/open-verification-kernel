# Verifier-assurance guide (OVK-VA-01…14)

Opt-in assurance mode for reproducible verifier execution, configuration snapshots, evidence packs, replay, and typed mutation. Ordinary `ovk check` / MCP / Action paths are unchanged and do not require `pcs-core`.

## Modes

| Mode | Entry points | Requires pcs-core? | Default? |
|---|---|---|---|
| Ordinary CI | `ovk check`, `ovk verify`, GitHub Action, MCP | No | Yes |
| Assurance | `ovk verifier …` | Yes (resolved pin) | No (opt-in) |

## Install

### Ordinary (default)

```bash
pip install -e .
# or: pip install open-verification-kernel
```

### Assurance (opt-in)

```bash
pip install -e ".[assurance]"
# installs pcs-core at the git commit documented in PCS_PIN.md
# Sibling editable remains a local fallback:
pip install -e "../pcs-core/python"
# or set OVK_PCS_CORE_PATH to a pcs-core checkout
```

See [PCS_PIN.md](../PCS_PIN.md). Pin identity for merge-to-main is satisfied at the documented pcs-core commit. PyPI publish of pcs-core remains pending.

Optional native toolchains (not required for ordinary CI):

| Tool | Assurance backend | Missing behavior |
|---|---|---|
| `opa` | `opa-policy` | typed `missing_checker` indeterminate |
| `lean` / `lake` | `lean-pfcore` | typed `missing_checker` indeterminate |
| `pytest` | `pytest-suite` | typed `missing_checker` if pytest import fails |

## CLI

```bash
ovk verifier describe --backend auth-state-predicate
ovk verifier snapshot-config --backend auth-state-predicate --out profile.json
ovk verifier run --backend auth-state-predicate --input input.json --evidence-dir evidence/
ovk verifier replay invocation.json --evidence-dir evidence/ --backend auth-state-predicate
ovk verifier mutate --profile profile.json --mutation mutation.json --out mutated.json
ovk verifier validate-evidence evidence/
```

## Assurance-capable backends

| `backend_id` | VA | Mechanism | Guarantee class | Determinism |
|---|---|---|---|---|
| `auth-state-predicate` | VA-06 | Exact predicates over declared authoritative state | observational | deterministic |
| `pytest-suite` | VA-07 | Real pytest runner + junit capture | runtime_observed | deterministic |
| `opa-policy` | VA-08 | Real `opa eval` | certificate_checked | deterministic |
| `lean-pfcore` | VA-09 | Real `lean` / optional `lake env lean` | formally_checked | deterministic |
| `sql-state-diff` | VA-10 | SQLite before/after state digests | observational | deterministic |
| `model-judge` | VA-11 | Stochastic judge (CI contract fake) | empirically_measured | stochastic |

Ordinary `opa-native`, `deployment-deterministic`, and external `lean` (`deterministic_fallback`) are **not** assurance_capable. Cedar is never assurance_capable in this programme.

## Evidence packs

Layout under `evidence/`:

```text
invocation.json                 # VerifierInvocationRecord.v1 (PCS)
verifier_profile.pcs.json       # VerifierProfile.v1 (PCS)
verification_result.pcs.json    # VerificationResult.v1 (PCS)
compiled_obligation.json        # OVK-local sidecar
raw/  normalized/  provenance/  # OVK-local sidecars
```

Replay writes `replay_report.pcs.json` (`VerifierReplayReport.v1`). Mutation writes a sealed `VerifierMutationManifest.v1` beside the mutated profile. See [PCS_PIN.md](../PCS_PIN.md).

Committed examples (no OPA/Lean toolchain required): [examples/assurance/](../../examples/assurance/). OPA / Lean packs are produced locally with `ovk verifier run` when those tools are installed; missing tools must yield typed indeterminate, never fabricated passes.

PCS artifacts in the pack are validated fail-closed against the pin. Results bind an opaque `invocation_ref` (`invocation_id` + `invocation_digest` only).

Validate:

```bash
ovk verifier validate-evidence examples/assurance/auth-state-predicate
```

## Conformance (VA-12)

Shared 14-test matrix in `ovk.assurance.conformance` / `tests/assurance/test_conformance_and_adjudication.py`. Any adapter claiming `assurance_capable=True` must pass (tool-absent paths only via typed indeterminate, never fabricated passes).

## Adjudication import (VA-13)

Post-freeze only. Hidden/active holdout labels are refused in adjudication refs and `ovk verifier run` inputs. Audit events append to an optional JSONL log.

## Non-claims

OVK verifier-assurance does **not**:

- run RL training, attack orchestration, or campaign statistics
- simulate production environments beyond declared fixtures
- treat model-judge scores as formal or certificate-checked results
- upgrade guarantee class during normalization
- invent native passes when `opa` / `lean` / checkers are missing
- promote Cedar or ordinary Lean `deterministic_fallback` to assurance
- expose FormalPR-Holdout hidden labels to policies or verifiers
- replace ordinary `ovk check` evidence with PCS packs (modes are separate)
- claim that a development path-pin of pcs-core is a published supply-chain pin

## Quality bar

- `ruff` / pytest for assurance packages
- PCS schema validation fail-closed when pin present; fail-closed when pin required and missing
- Secret redaction before snapshot/profile export
- Reproducible evidence packs with nested integrity digests
- Supply-chain: pin pcs-core; do not fork PCS schemas under `schemas/`
- Mutation never overwrites production profiles; overwrite attempts refuse closed

## Related

- [ADAPTER_INVENTORY.md](ADAPTER_INVENTORY.md)
- [PCS_PIN.md](../PCS_PIN.md)
- [ADR 0001](../adr/0001-verifier-assurance-architecture.md)
- [CHANGELOG_VERIFIER_ASSURANCE.md](../CHANGELOG_VERIFIER_ASSURANCE.md)
- [THREAT_MODEL.md](../THREAT_MODEL.md)
- [BACKENDS.md](../BACKENDS.md)
