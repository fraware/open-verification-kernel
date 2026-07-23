# Experimental and Non-Strict Paths

Honest limits for compiler and backend paths that exist in-repo but are **not**
production-strict exits. This document does not claim vision completion or
Beta → Production graduation.

## Source-grounded compilers (wired)

| Path | Hot path | Strict allow |
|---|---|---|
| FastAPI / Express authorization | Yes — when base+head materials are supplied | Only with `complete` coverage, or explicit `coverage.accept_partial_coverage` |
| Terraform plan / Kubernetes IR | Yes — when plan/objects are present | Incomplete / unsupported constructs force review eligibility |
| GitHub Actions trust-flow | Yes — when workflow YAML/`document` materials are present | Findings participate in CI-secrets enforcement |
| Deployment explicit / environments / Argo | Yes — when materials match a compiler | Partial state machines cannot claim complete coverage |
| Legacy pre-normalized JSON abstractions | Still supported | Do **not** claim source-grounded coverage |

Before/after reconstruction requires **both** base and head materials. Head-only
inputs yield `unknown` coverage and cannot allow under strict policy.

## CBMC registration

`ovk.core.cbmc_compiler.compile_cbmc_obligation` registers CBMC materials honestly:

| Compiler id | Meaning |
|---|---|
| `ovk.cbmc.project_grounded.v1` | Harnesses include project code **and** function targets exist |
| `ovk.cbmc.harness_or_cdb.v1` | Harness or compile DB present without project-grounded claim |
| `ovk.cbmc.registry.v1` | No materials — registered without strict eligibility |

Do not rename weaker guarantees to imply project-model checking.

## Native subprocess backends

OPA / CBMC / Cedar CLI runs go through `LocalSubprocessWorker`:

* timeouts → `unknown` / error termination — never deterministic pass fallback
* secret-bearing env vars are not inherited
* cwd can be bound to allowed roots

Absence of a native binary remains `unknown`, never fabricated pass.

## Control-plane cache

Enforced/shadow control-plane paths use `HardenedResultCache` namespaces with
key-component validation. Subject, routing, policy-digest, and environment
mismatches are cache misses — stale results must not authorize allow.

## Sprint 13 external exits

| Path | Status |
|---|---|
| Pilot ledger schema — `schemas/pilot.ledger.schema.json` | Active scaffolding (seeded `automated_scenario` rows only) |
| Consumer validation checklist — `docs/CONSUMER_VALIDATION_CHECKLIST.md` | Live consumers: `fraware/ovk-consumer-fastapi-terraform`, `fraware/ovk-consumer-express-actions` |
| FormalPR-Holdout — private `fraware/FormalPR-Holdout`, see `docs/FORMALPR_HOLDOUT_GOVERNANCE.md` | Active program (synthetic seed); not a production generalization claim |
| Sigstore protected-release E2E | See [RELEASE.md](RELEASE.md) / current branch work |

## Metric provenance

Generated badge/summary/adoption metrics must carry `verified_source_sha` for
the commit that produced the numbers. Later `[skip ci]` badge commits must not
be cited as the verified source. See program §24.3.
