# OVK Release Status

Living release/adoption status for Open Verification Kernel.

**Last reviewed:** 2026-08-26

**Current judgment:** `1.3.0-rc.1` is an **engineering release candidate under final review in PR #23** (`hardening/final-release-closure-2026-08-25`). It is not yet an attributable `v1.3.0-rc.1` release. The last previously signed immutable release remains `v1.2.1`; evidence from that tag must not be re-attributed to the RC source tree.

The authoritative publication procedure is [RELEASE.md](RELEASE.md). The evidence threshold is [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md). The generated TCB is [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md).

## Release authority

The repository deliberately separates three concepts:

| Concept | Current meaning |
|---|---|
| Development candidate | Source SHA being tested in PR/push CI |
| `benchmark_source_sha` | Source SHA measured by FormalPR-Bench/badge artifacts |
| `verified_source_sha` | Source SHA minted only by the complete live release-ledger authorizer |

For `v1.3.0-rc.1`, **`verified_source_sha` is currently unset**. It must not be entered manually in this document or inferred from green PR CI. `scripts/verify_release_ledger_github.py` is the only release-authority path: it independently resolves exact GitHub Actions run IDs, verifies required holdout/consumer artifacts, binds the exact wheel/sdist bytes, and only after the complete evidence scope succeeds may it authorize the ledger.

Offline structural ledger validation does not authorize a release.

## What is implemented in the RC tree

- five bounded verification lanes: self-protection, authorization, infrastructure exposure, CI-secrets exposure, and deployment approval state;
- normative `DecisionState` aggregation and explicit unknown/review outcomes;
- evidence-integrity and controlling-finding reconstruction;
- source-profile support contracts and maturity labels that remain below externally calibrated strictness;
- capability registry and adapter-conformance honesty gates;
- FormalPR-Bench provenance/partition infrastructure for **internal regression**, not external accuracy calibration;
- label-separated FormalPR-Holdout prediction/evaluation workflows;
- exact candidate-bound consumer-pin evidence for two independent consumer repositories;
- native required-matrix checks for OPA, Z3, CBMC, and Cedar-related integration surfaces according to their documented backend semantics;
- multi-OS reproducibility harness for Linux/macOS/Windows × Python 3.10/3.12;
- SHA-pinned third-party actions on OVK release surfaces;
- authorization-first Publish workflow with exact distribution hashing, keyless Sigstore, private GitHub Release staging, PyPI Trusted Publishing, and independent PyPI read-back before public GitHub Release publication.

These implementation facts do not imply universal formal verification, external calibration, or production-stable enforcement for arbitrary repositories.

## Public maturity / claim boundaries

| Surface | Claim boundary |
|---|---|
| FormalPR-Bench | Internal curated regression suite only; not an independent accuracy estimate |
| Source profiles | Current generated profiles are `executable_advisory`; `externally_calibrated_strict` is not claimed |
| OPA/Z3/CBMC adapters | Preview native paths; guarantees are bounded by exact compiler/input/tool assumptions documented in [BACKENDS.md](BACKENDS.md) |
| Cedar/TLA+/Kani/Dafny/Verus/Lean/Alloy catalog paths | Experimental unless their capability registry says otherwise; several are deterministic contract/evidence paths rather than native proof execution |
| Composite Action | Suitable for pinned advisory evaluation; strict required-check use remains repository-specific and calibration-dependent |
| GitHub App | Private alpha, not Marketplace/public production surface |
| Pilot evidence | In-repository dogfood and published advisory pilot reports are not independent human calibration |

Unsupported or untrusted inputs must not silently become `allow`. The intended safety posture is conservative: explicit unknown/review outcomes are preferable to unsupported success claims.

## Pre-tag development gate

The exact final candidate SHA must pass all of the following after the last code/document change:

- [ ] CI, including lint and the complete unit/integration suite;
- [ ] release preflight and generated-document freshness gates;
- [ ] package build and outside-checkout wheel smoke;
- [ ] composite Action advisory/strict dogfood;
- [ ] template conformance;
- [ ] all six Repro baseline OS/Python cells;
- [ ] Native Backends Tier 1;
- [ ] Native Backends Tier 1b.

A historical green SHA is not enough after the tree changes. The final exact-head matrix is the pre-tag engineering gate.

## Tag-bound release authorization gate

After the engineering candidate is frozen and a signed annotated tag is created, release authorization requires **new** `workflow_dispatch` runs on that exact tag for:

1. `CI`;
2. `Repro baseline`;
3. `Native Backends Tier 1`;
4. `Native Backends Tier 1b`;
5. `FormalPR-Holdout predict`;
6. `FormalPR-Holdout eval`;
7. `Consumer Pin Verification`.

PR runs are not reused as final release evidence.

The holdout evaluator must consume the prediction artifact from an explicit prior prediction run ID and verify candidate/digest identity before label access. The consumer verifier must retain evidence for both required independent consumer repositories pinning the exact 40-hex candidate.

## Publication gate

The production sequence is intentionally authorization-first:

```text
signed annotated tag
  -> seven tag-bound release-evidence runs
  -> live release-ledger authorization
  -> exact wheel/sdist byte recheck
  -> Sigstore sign + verify + tamper test
  -> private GitHub Release draft
  -> PyPI Trusted Publishing
  -> exact PyPI filename/SHA-256 read-back
  -> make the existing GitHub Release public
```

A public GitHub Release is never used as the trigger for authorization. Maintainers must not manually create the release beforehand; Publish owns the draft-to-public transition.

Safe recovery after a partial PyPI/GitHub failure is allowed only when existing PyPI filenames and SHA-256 values exactly equal the authorized local distributions. Blind `skip-existing` behavior is forbidden.

## Adoption recommendation

| Mode | Recommendation |
|---|---|
| Local/demo | Appropriate for inspecting supported lanes, assumptions, and artifacts |
| Advisory Action | Appropriate for pilots when pinned to an immutable released tag/commit and outputs are adjudicated |
| Strict required check | Repository-specific only after trusted inputs and empirical calibration for the intended lane |
| General production-stable enforcement | **Not claimed** |

Until an attributable `v1.3.0-rc.1` release exists, do not present that tag as a live install pin. Historical `v1.2.1` remains a separate immutable release with its own source and signing evidence.

## Remaining external/maintainer evidence for the RC

These cannot be truthfully marked complete merely from repository code:

- [ ] freeze the exact final candidate after its complete development matrix is green;
- [ ] create and push the signed annotated `v1.3.0-rc.1` tag;
- [ ] execute all seven tag-bound release-evidence workflows;
- [ ] retain governed holdout and consumer artifacts for those exact run IDs;
- [ ] obtain a fully authorized release ledger and its `verified_source_sha`;
- [ ] complete tag-bound Sigstore signing/verification;
- [ ] complete PyPI Trusted Publishing and exact read-back;
- [ ] publish the staged GitHub Release only after the PyPI equality gate succeeds.

Promotion beyond the RC requires the additional independent-validation conditions described in [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md); automated fixtures and internal benchmarks must remain distinct from independent human calibration.

## Key references

| Document | Purpose |
|---|---|
| [RELEASE.md](RELEASE.md) | Exact maintainer release procedure and recovery semantics |
| [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md) | Release evidence/authority checklist |
| [TRUSTED_COMPUTING_BASE.md](TRUSTED_COMPUTING_BASE.md) | Generated TCB and pinned release surfaces |
| [STATUS.md](STATUS.md) | Generated source-profile maturity status |
| [BACKENDS.md](BACKENDS.md) | Exact backend maturity and guarantee classes |
| [BENCHMARK.md](BENCHMARK.md) | FormalPR-Bench scope and provenance limits |
| [FORMALPR_HOLDOUT_GOVERNANCE.md](FORMALPR_HOLDOUT_GOVERNANCE.md) | Holdout governance and leakage boundary |
| [HOLDOUT_LABEL_SEPARATION.md](HOLDOUT_LABEL_SEPARATION.md) | Prediction/evaluation separation |
| [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) | Independent consumer evidence contract |
| [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) | Independent advisory pilot methodology |
