# OVK Release Status

Living adoption dashboard for Open Verification Kernel.

**Last updated:** 2026-07-23

**Release judgment:** **`v1.3.0-rc.1` candidate**. The typed backend control plane post-dates signed `v1.2.1` (`a27d5720f4350c00bca34f71d991c31f5a2f38c7`). Default product path remains shadow/legacy-authoritative; enforced routing is lane-policy opt-in until P0 trust closure. Do not treat current `main` as a re-validation of signed `v1.2.1`.

Authoritative audit: [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md). Engineering program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md). Historical: [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) (superseded for day-to-day status).

## At a glance

| Signal | Current state |
|---|---|
| **Package version** | Working tree targets future `v1.3.0-rc.1`; signed immutable tag remains `v1.2.1` only for that tag’s commit |
| **FormalPR-Bench** | Internal curated regression; report `benchmark_source_sha` separately from `verified_source_sha` |
| **Check types** | Five bounded production lanes: self-protection, authorization, infrastructure, CI secrets, deployment |
| **Backend execution** | Typed `BackendControlPlane` + `route_obligation`; five policy-selectable enforced lanes via `adapter_runtime` |
| **Routing** | Enforced under lane policy; default path still shadow/legacy-authoritative until P0 closure |
| **Unit and workflow tests** | Local Sprint 0 baseline recorded below; live GitHub Actions workflow IDs still pending |
| **Package portability** | Local wheel-outside-checkout import smoke passed on working tree (package metadata still `1.2.1` until rc.1 cut) |
| **GitHub Action** | Consumers still live-pin `v1.2.1`; local consumer clones prepared for `v1.3.0-rc.1` (not pushed) |
| **External validation** | In-repository dogfooding + consumer scaffolding; independent pilots incomplete |
| **Sigstore** | Immutable-tag E2E closed for `v1.2.1` only — not attributable to typed control-plane commits |

OVK is not complete formal verification of arbitrary code. It provides explainable, conservative checks for a bounded set of high-risk changes and emits explicit unknown and human-review outcomes.

## Source SHA terminology

| Field | Meaning | When to set |
|---|---|---|
| `benchmark_source_sha` | Commit whose FormalPR-Bench (or badge) artifacts were measured | Any bench/badge run |
| `verified_source_sha` | Commit with a **complete observed required-workflow set** | Only after Sprint 0 / release gates attach live workflow IDs |

Badge-only or `[skip ci]` commits must set `benchmark_source_sha` and must **not** be labeled `verified_source_sha`.

## Local Sprint 0 baseline

Local evidence only. Distinguishes from GitHub Actions workflow IDs (still pending). Working tree HEAD at measurement time: `4b48ab245193e177a6d95e8557332334a9bd2883` (badge `[skip ci]` tip — treat as `benchmark_source_sha`, not verified).

| Gate | Command | Exit | Timestamp (local) |
|---|---|---|---|
| Focused R2 + enforcement pytest | `python -m pytest tests/test_source_profile_hardening.py tests/test_template_conformance.py tests/test_verified_source.py tests/test_bench_badge.py tests/test_formalpr_holdout_runner.py tests/test_execution_models.py tests/test_cache_worker_control_plane.py tests/test_adapter_isolation_r2_pr8.py tests/test_evidence_v3_r2_pr9.py tests/test_authorization_enforcement.py tests/test_adversarial_control_plane.py tests/test_source_profiles.py -q` | **0** (111 passed) | 2026-07-23T23:41:09-07:00 → 23:42:03 |
| Broader compiler/cache suite | `python -m pytest tests/test_authorization_compilers.py tests/test_infrastructure_compilers.py tests/test_github_actions_trust.py tests/test_remaining_lane_enforcement.py tests/test_self_protection_enforcement.py tests/test_verification_cache.py tests/test_result_cache_semantics.py -q` | **0** (54 passed) | 2026-07-23T23:35:44-07:00 |
| Sprint 6–8 regression | `python -m pytest tests/test_source_profile_hardening.py tests/test_template_conformance.py tests/test_formalpr_holdout_runner.py tests/test_source_profiles.py tests/test_authorization_compilers.py tests/test_infrastructure_compilers.py -q` | **0** (46 passed) | 2026-07-23T23:40:48-07:00 |
| Release preflight (`PYTHONPATH=.`) | `python scripts/release_preflight.py` | **0** | 2026-07-23T23:44:17-07:00 → 23:45:10 |
| Template validation | `python scripts/validate_templates.py` | **0** | 2026-07-23T23:41:09-07:00 |
| Template conformance v2 regenerate | `python scripts/build_template_conformance.py` | **0** (`source_profile_strict_eligible=3`, `executable_advisory=2`, `catalog_only=95`) | 2026-07-23T23:40:57-07:00 |
| Local release smoke | `python scripts/smoke_release_local.py` | **0** | 2026-07-23T23:41:09-07:00 |
| Wheel build + outside-checkout import | `python -m build --wheel` then `pip install … -t $TEMP/ovk-outside-import` and `import ovk` | **0** (`verified_source_sha` correctly `None` outside attested env) | 2026-07-23T23:46:01-07:00 → 23:46:29 |
| Workflow ID collector | `python scripts/collect_workflow_evidence.py --sha <HEAD> --output .verification/workflow-evidence-local.json` | **0** (0 runs on `[skip ci]` tip; `verified_source_sha` left unset) | 2026-07-23T23:46:29-07:00 |

### Still pending (live GitHub Actions / secrets)

| Gate | Status | Evidence |
|---|---|---|
| General CI / unit+gates on non-`[skip ci]` SHA | Pending live run | Record run URL when available |
| Native Tier 1 | Pending | — |
| Action dogfood | Pending | — |
| Expanded FormalPR-Bench on release SHA | Pending | Use `benchmark_source_sha` |
| Adversarial release-bundle in Actions | Pending | Local `verify_release_bundle.py` entrypoint present |
| Label-separated holdout live eval | Pending | Needs `HOLDOUT_DOWNLOAD_TOKEN` + `HOLDOUT_ASSET_SHA256` |
| Consumer remotes on rc.1 | Pending push | Local clones prepared under `%TEMP%\ovk-consumer-prep\` (not pushed) |

## Adoption readiness

| Mode | Current recommendation | Conditions |
|---|---|---|
| **Local/demo** | Appropriate after current local/CI green | Use shipped examples and inspect assumptions and limits |
| **Advisory Action** | Appropriate for pilots on pinned tags | Prefer `v1.2.1` until rc.1 is attributable; collect FPs/unknowns |
| **Strict required check** | Repository-specific only | Calibrate on real diffs; trusted abstraction sources; protected policy metadata |
| **Production-stable general enforcement** | Not yet | P0 code (PRs 1–9) in working tree; still needs consumers on rc.1, attributable holdout, and Sprint 0 live gates |

Suggested rollout: local validation → advisory artifacts → advisory check run/comment → calibrated strict lane → protected required check.

## P0 trust defects (R2 PRs 1–9) — working-tree status

Code for PRs 1–9 is present in this working tree (attempt identity excludes `duration_ms`; `ovk.cache.v3` / `CachedBackendExecution`; coverage/guarantee fail-closed; fallback v2 blocking terminations; `metadata_trusted` default false; authoritative routing pipeline; worker isolation; `ovk.evidence.v3` material-set binding). Historical defect inventory: [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md). Program: [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md).

**Still open for attributable release (external / Sprint 0–10):** live non-`[skip ci]` workflow IDs, consumer repo pins on immutable rc.1, label-separated holdout aggregates, and signed publication gates — see checklists below and [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md).

## Sprint 6–10 working-tree progress

| Sprint | Local status |
|---|---|
| 6 Source profiles | FastAPI AST compiler; Terraform recursive modules; K8s controller reachability; Actions permissions-flow prover; deployment trusted-profile gate |
| 7 Template conformance v2 | Statuses derived from executed profile evidence (`source_profile_strict_eligible=3`; no `externally_calibrated_strict` from local gen) |
| 8 Holdout separation | `digest_holdout_predictions.py` + label-free guards; eval path token-stripped |
| 9 Consumers | In-repo template + checklist for rc.1; local clones pin-prepped (no push) |
| 10 Publication | [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md) + `scripts/collect_workflow_evidence.py` |

## Maintainer release gates

Before tagging or publishing **`v1.3.0-rc.1`**:

- [ ] run all CI and native Tier 1 jobs on a non-`[skip ci]` source commit;
- [ ] confirm wheel smoke from a directory outside the checkout;
- [ ] confirm automatic-diff composite Action dogfood;
- [ ] confirm package version matches the release tag;
- [ ] run full expanded FormalPR-Bench and release preflight;
- [ ] validate a complete release bundle, including evidence-quality semantics;
- [ ] exercise HMAC signing and identity-bound Sigstore signing according to release policy;
- [ ] run the immutable Action or release wheel in both independent consumer repositories at the rc.1 pin;
- [ ] update status with exact `verified_source_sha` and workflow links;
- [ ] confirm P0 trust PRs 1–9 on the exact tag source and record attributable holdout aggregates;
- [ ] keep the package classifier at Beta until independent pilots and P0 closure meet the production gate.

Promotion to **`v1.3.0`** additionally requires P0 closure + consumer + holdout evidence per [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md). Do not re-attribute `v1.2.1` Sigstore evidence to typed-control-plane commits.

## Related documents

| Document | Purpose |
|---|---|
| [DEEP_AUDIT_2026-07-23_R2.md](DEEP_AUDIT_2026-07-23_R2.md) | Authoritative R2 deep audit |
| [ENGINEERING_PROGRAM_2026-07-23_R2.md](ENGINEERING_PROGRAM_2026-07-23_R2.md) | Sprint/PR execution program |
| [SOURCE_PROFILE_HARDENING.md](SOURCE_PROFILE_HARDENING.md) | Sprint 6 profile status |
| [HOLDOUT_LABEL_SEPARATION.md](HOLDOUT_LABEL_SEPARATION.md) | Sprint 8 prediction/eval split |
| [CONSUMER_VALIDATION_CHECKLIST.md](CONSUMER_VALIDATION_CHECKLIST.md) | Sprint 9 consumer pins |
| [ATTRIBUTABLE_PUBLICATION.md](ATTRIBUTABLE_PUBLICATION.md) | Sprint 10 publication gate |
| [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) | Historical pre-control-plane audit |
| [STATUS.md](STATUS.md) | Command and lane inventory |
| [BACKENDS.md](BACKENDS.md) | Exact backend execution maturity and guarantee classes |
| [INTEGRATION.md](INTEGRATION.md) | Installation and GitHub Action setup |
| [RELEASE.md](RELEASE.md) | Maintainer release procedure |
| [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) | Independent advisory pilot process |
| [BENCHMARK.md](BENCHMARK.md) | Internal benchmark format and execution |
