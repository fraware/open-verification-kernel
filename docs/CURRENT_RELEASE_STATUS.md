# OVK Release Status

Living adoption dashboard for Open Verification Kernel.

**Last updated:** 2026-07-22

**Release judgment:** v1.2.0 **release candidate**. The bounded evidence pipeline is substantial, but the complete solver-agnostic kernel vision is still partial because backend routing does not yet control execution. A fresh green CI run and independent tagged-consumer validation are required before calling the release production-stable.

Authoritative audit: [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md).

## At a glance

| Signal | Current state |
|---|---|
| **Package version** | `1.2.0` release candidate; PyPI and immutable release-tag state must be confirmed by maintainers |
| **FormalPR-Bench** | Repository snapshot reports 130/130 curated regression cases; this is internal conformance, not an external accuracy estimate |
| **Check types** | Five bounded production lanes: self-protection, authorization, infrastructure, CI secrets, deployment |
| **Backend execution** | OPA and Z3 native paths; CBMC bounded explicit/template harness path; Cedar version probe plus deterministic evaluator; six deterministic contract adapters |
| **Routing** | Candidate routing is computed and recorded; selected backends do not yet control lane execution |
| **Unit and workflow tests** | Not independently observed for the current audited source commit; latest observed HEAD is a `[skip ci]` badge commit |
| **Package portability** | Wheel-outside-checkout smoke has been added to CI and must pass on the current source SHA |
| **GitHub Action** | Automatic PR-diff collection and quoted arguments are implemented; independent tagged consumer repository remains pending |
| **External validation** | Current workflow is in-repository dogfooding; external pilot registry contains no completed independent pilot evidence yet |

OVK is not complete formal verification of arbitrary code. It provides explainable, conservative checks for a bounded set of high-risk changes and emits explicit unknown and human-review outcomes.

## Adoption readiness

| Mode | Current recommendation | Conditions |
|---|---|---|
| **Local/demo** | Appropriate after current CI is green | Use shipped examples and inspect assumptions and limits |
| **Advisory Action** | Appropriate for pilots after current CI is green | Collect adjudicated false positives, unknowns, and missed detections |
| **Strict required check** | Repository-specific only | Calibrate on real diffs; use trusted abstraction sources and protected policy metadata |
| **Production-stable general enforcement** | Not yet | Requires enforced backend routing, source-grounded compilers, independent pilots, and attributable release CI |

Suggested rollout: local validation → advisory artifacts → advisory check run/comment → calibrated strict lane → protected required check.

## Current high-priority gaps

1. Backend routing is advisory metadata and does not control compilation or execution.
2. The 100-template catalog does not equal 100 executable, end-to-end properties.
3. Authorization, infrastructure, CI workflow, and deployment diff extraction remain heuristic.
4. Cedar and six other external adapters do not perform native proof/policy execution.
5. FormalPR-Bench is an internal curated regression corpus without an independent holdout.
6. No completed independent repository currently proves the tagged Action and wheel integration.
7. Current-commit CI evidence is not attached to the latest observed `[skip ci]` HEAD.
8. Auto-collected branch protection cannot reconstruct removed required checks without trusted before/after data.
9. Live Sigstore keyless signing: protected `workflow_dispatch` dry-run succeeded ([run 30008891551](https://github.com/fraware/open-verification-kernel/actions/runs/30008891551); `sigstore` environment + retained cosign bundles). **Immutable-tag Release E2E** (production pin) remains open — see [RELEASE.md](RELEASE.md#sigstorecosign-keyless).

Full analysis and acceptance criteria: [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md).

## Maintainer release gates

Before tagging or publishing v1.2.0:

- [ ] run all CI and native Tier 1 jobs on a non-`[skip ci]` source commit;
- [ ] confirm wheel smoke from a directory outside the checkout;
- [ ] confirm automatic-diff composite Action dogfood;
- [ ] confirm package version matches the release tag;
- [ ] run full expanded FormalPR-Bench and release preflight;
- [ ] validate a complete release bundle, including evidence-quality semantics;
- [ ] exercise HMAC signing and identity-bound Sigstore signing according to release policy;
- [ ] run the immutable Action or release wheel in an independent consumer repository;
- [ ] update status with exact source SHA and workflow links;
- [ ] keep the package classifier at Beta until independent pilots and backend-routing enforcement meet the production gate.

## Related documents

| Document | Purpose |
|---|---|
| [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md) | Current deep code, artifact, vision, and engineering audit |
| [STATUS.md](STATUS.md) | Command and lane inventory |
| [BACKENDS.md](BACKENDS.md) | Exact backend execution maturity and guarantee classes |
| [INTEGRATION.md](INTEGRATION.md) | Installation and GitHub Action setup |
| [RELEASE.md](RELEASE.md) | Maintainer release procedure |
| [EXTERNAL_PILOT_PLAYBOOK.md](EXTERNAL_PILOT_PLAYBOOK.md) | Independent advisory pilot process |
| [BENCHMARK.md](BENCHMARK.md) | Internal benchmark format and execution |
