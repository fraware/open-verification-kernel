# External OSS pilot playbook — advisory evaluation

This playbook governs **consented, non-blocking** use of Open Verification Kernel (OVK) in an independently operated repository. An external pilot is a test of customer utility and the declared verification profile, **not** proof of general source-level security, production readiness, or verified economic savings.

The current public status identifies source profiles as `executable_advisory`. No `externally_calibrated_strict` source-profile qualification is established. A small pilot must never automatically promote a check to strict or to a required merge gate.

## 0. Obtain consent and qualify the repository

Before adding any GitHub workflow, obtain approval from the maintaining organization, identify a reviewer and a technically responsible operator, and agree on which evidence is safe to retain or publish. Do not install CI into someone else's repository without permission.

Record the target repository and exact PR revision, the declared check family, its supported source constructs and exclusions, the intended high-risk operation, the reviewer decision, and the organization's actual need. A changed authentication-related file is **not** sufficient proof that OVK supports the code's authorization semantics. Keep unsupported shapes **unknown** and subject to human review.

Start with one available check family. The historical example manifests include:

| Check family | Potential starting problem | Starter manifest |
| --- | --- | --- |
| CI secrets | Changes to workflow secret exposure | [CI secrets template](templates/pilot_manifest_ci_secrets.template.json) |
| Self-protection | Changes to agent CI gates | `examples/pilot_repos/self_protection_only.json` |

The FastAPI authorization / Protected Effect path is a separate bounded advisory research profile. It must first pass source-eligibility and coverage screening; do not substitute the CI-secrets example for proof of route authorization.

## 1. Install a released, attributable advisory build

Use the [current release status](CURRENT_RELEASE_STATUS.md), [release procedure](RELEASE.md) and an exact vetted release/ref identity. The historic `v1.2.1` example below is a **reference only**: confirm the remote tag and distribution integrity for the installation, and never treat a draft `v1.3.0-rc.1` as a published release on the strength of green development CI.

Copy `docs/templates/pilot_manifest_ci_secrets.template.json` into the consenting repository as `.verification/ci_secrets_pilot.json`, and replace sample inputs with real, explicitly in-scope paths. Do **not** treat `examples/ci_secrets/input_secrets_safe.json` as coverage of the adopter's code.

The action should use least privileges and no automatic comments on untrusted fork PRs. Example starting point (adapt to the target repository's branch and trust settings):

```yaml
name: OVK advisory pilot
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  ovk-advisory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Build PR diff
        run: |
          git fetch origin "${{ github.base_ref }}"
          git diff "origin/${{ github.base_ref }}...HEAD" > ovk-pr.diff
      - name: OVK advisory check
        uses: fraware/open-verification-kernel@v1.2.1
        with:
          mode: advisory
          use-check: "true"
          changed-files: ovk-pr.diff
          post-comment: "false"
      - name: OVK advisory verification
        uses: fraware/open-verification-kernel@v1.2.1
        with:
          mode: advisory
          verification-manifest: .verification/ci_secrets_pilot.json
          bundle-output-dir: ovk-pilot-bundle
          post-comment: "false"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ovk-pilot-artifacts
          path: |
            ovk-evidence.json
            ovk-pilot-bundle/**
          retention-days: 30
          if-no-files-found: warn
```

Review the actual code and external actions before enabling this workflow. A pinned immutable SHA is preferable once the maintainer has verified the exact source identity. The check stays advisory, cannot authorize a merge, and does not receive secrets from untrusted PRs.

## 2. Observe all naturally occurring PRs

Begin with a 14-day window. Collect **all** natural PRs in the consented scope, not a favorable selection. A target of five PRs is useful to test deployment feasibility, **not** a safety or false-negative-rate threshold. Extend the observation window if activity is low.

For each PR, record the exact base/head SHAs, source and verifier version, declared claim, supported/unsupported/unknown input, raw evidence and assumptions, report viewed by the reviewer, actual reviewer decision, adjudicated incorrect alerts, independently discovered misses, setup and review time, and fixes or rechecks. Record missing observations as missing—not as zeros. Keep private source and evidence out of the public registry unless explicitly approved.

If the pipeline reports a `PASS`, communicate the **typed checker/IR claim under its exact coverage assumptions**. Never summarize it as proof that an arbitrary source application is secure. If extraction is partial or an operation is outside the admitted profile, the outcome is unresolved.

## 3. Compute metrics with correct provenance

The ingest command is:

```bash
python scripts/ingest_external_pilot_metrics.py \
  --repo org/repo --artifacts-dir ./artifact \
  --report ./external_pilot_report.json
python scripts/render_pilot_metrics.py \
  --registry docs/benchmarks/external-pilots-registry.json
```

The optional report starts from [external_pilot_report.template.json](templates/external_pilot_report.template.json); replace its placeholders. Even if a file named `external_pilot_report.json` appears within a downloaded CI artifact directory, the ingester **does not automatically adopt its adjudication fields**. A human operator must deliberately select a separately reviewed report via `--report`, with the same repository identifier as `--repo`. Such reports remain self-reported until independently audited. `prs_evaluated`, `prs_blocked`, and latency can come from workflow artifacts. **False positives require separate human or independently specified ground-truth adjudication.** OVK's own `passed`, `merge_recommendation`, and checker `PASS/FAIL` fields are not ground-truth labels. The metric ingester must not manufacture a false-positive rate from them.

Only supply `false_positives` and `false_positive_rate` if a reviewer actually classified cases and the denominator and decisions are documented in the report's linked evidence or notes. Otherwise leave both `null`. If a new artifact cohort arrives without fresh adjudication, previously reported rates are stale and must not be carried forward as current measurements. A reviewer-provided number is still **self-reported** until independently audited.

Explicitly distinguish:
- **Check/recommendation rate:** what OVK returned on actual PRs.
- **Adjudicated false alarms:** the reviewer judged the tool's finding incorrect, with a defined denominator.
- **Independently found misses:** issues found by a separate source of truth that OVK did not flag, including unsupported cases.
- **Coverage/unknown fraction:** what proportion of natural PRs and relevant constructs fell outside the supported profile.
- **Economics:** reviewer minutes, CI latency/cost, integration effort and rechecks; compare with a credible baseline.

Small selected samples, even with zero observed false positives, cannot justify a general low-risk claim.

## 4. Decision gate: continue, revise, or stop

**Continue advisory:** the maintainer actively uses the findings and they remain appropriately scoped, with transparent unknowns and manageable review costs.

**Revise:** coverage misses important high-risk changes, the result is difficult to interpret, or false alarms dominate. Improve the *supported profile* or workflow only with evidence from actual users.

**Stop or select a different wedge:** the relevant guarantee is outside the verifier's modeled semantics, no reviewer values the output, or no willing maintainer participates.

**Strict enforcement is a distinct qualification project.** It needs a justified source-model correspondence, trustworthy evidence/provenance, independent profile-appropriate safety evaluation with explicit unknown handling, security review, a controlled rollback plan, repository-specific risk approval, and release/ref integrity. No numeric false-positive threshold or five-PR fixture test automatically grants strict maturity.

## 5. Reporting and references

Publish a study only with maintainer permission and clearly label it as *independent external*, *maintained-consumer*, or *dogfood*. The existing [external pilot registry](benchmarks/external-pilots-registry.json) includes maintained and internal examples; they are not independent customer validation.

The adoption report and supporting paths are [PILOT_CASE_STUDIES.md](PILOT_CASE_STUDIES.md), `scripts/collect_pilot_metrics.py`, `scripts/ingest_external_pilot_metrics.py`, `scripts/render_pilot_metrics.py`, and `docs/benchmarks/external-pilots-registry.json`.

Operational ownership and milestones are tracked in [North Star issue #216](https://github.com/fraware/open-verification-kernel/issues/216), with the first independent pilot in [issue #20](https://github.com/fraware/open-verification-kernel/issues/20).
