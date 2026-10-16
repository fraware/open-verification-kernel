# PR source identity contract — merge-preview development v1

**Security and release prerequisite; non-controlling.** This change addresses [#222](https://github.com/fraware/open-verification-kernel/issues/222). It makes the Action's *default PR diff* refer to the same Git commit as the existing `--head-sha` evidence subject. It is **not** a complete authenticated verification receipt or a proof of source-to-model fidelity.

## Distinct objects

For a GitHub `pull_request`, the event reports `base.sha` and `head.sha`. The Actions `github.sha` normally identifies a GitHub-generated merge-preview commit, not the contributor head. `actions/checkout` normally checks out that merge preview. The previous Action built `git diff base head` yet wrote `github.sha` as the claim subject and targeted GitHub checks at `github.sha`. These differ when the merge tree differs from the PR head tree. A reliable system must never silently treat them as one object.

## Bounded new behavior

`scripts/prepare_verified_change_input.py`, invoked from `action.yml` after checkout, now:

1. Requires the actual checked-out commit to equal the full `github.sha` provided by the GitHub event. In the ordinary PR path, reads the commit's raw parent headers and requires precisely two parents: event `base.sha` and `pull_request.head.sha`, in that order.
2. Requires the base commit object to be available (attempting an explicit shallow fetch otherwise), with **no fallback** to `HEAD^ HEAD` or a different comparison on fetch failure. Computes `git diff --no-ext-diff --binary event-base checkout-merge` and its SHA-256. For non-PR push, compares the checked-out first parent to the checked-out commit. A root commit uses `git show`.
3. Writes a versioned `ovk-source-binding.json` sidecar recording the two event identities, evaluated commit/tree identity, exact diff SHA-256, input comparison mode, explicit limits on authentication/relying policy and whether input was structurally checked against the checkout.
4. Rejects mismatching or malformed commit IDs, incompatible PR parentage, and `pull_request_target`. Caller-selected change input remains supported **in advisory mode only**, and the sidecar marks it `caller_supplied_unbound`. A caller-selected input is refused in strict mode. To prevent an unbound advisory fixture from becoming a misleading shareable check or comment, the Action suppresses automatic GitHub Check and PR-comment emission for caller-selected input, and emits an explicit warning. The local advisory evidence can still be inspected as an experiment.
5. Makes this sidecar available among the existing Action artifacts. Existing `ovk check` evidence and check API calls still use `github.sha`, now consistently describing the checked-out **merge preview** for the ordinary default PR input.

The new test creates real base/head/merge Git commits, asserts the chosen binary diff, introduces wrong base/head/checkout identifiers, tests a contributor-only checkout, opaque inputs, `pull_request_target`, push, and failure without writing a misleading receipt.

## Explicit manifest safety boundary

The composite Action's `verification-manifest` mode accepts a caller-selected
manifest and checks the referenced materials under that manifest's own scope.
It does **not** execute the pull-request source-binding helper, so its
`subject.head_sha` alone does not establish that every changed PR construct
was assessed. Consequently an explicit manifest result is **local advisory
evidence only** in the Action:

- The manifest path does not publish a GitHub Check or PR comment, regardless
  of caller-supplied `emit-check` or `post-comment` inputs.
- `mode: strict` with `verification-manifest` is refused before evaluation.
  Strict PR enforcement cannot be synthesized from an unbound manifest.
- The composite Action outputs are deliberately `decision_state=unknown`,
  `recommendation=require_human_review`, and `exit_code=2` for any
  manifest input, even if the selected manifest's own scoped verifier reports
  `allow`. The same Action-level downgrade applies to any caller-supplied
  `changed-files` diff. Only the internally prepared default change input
  retains its scoped decision in Action outputs; neither form of unbound input
  grants an `allow` output suitable for downstream PR approval.
  The selected input's own result remains in local advisory artifacts.
- All reserved top-level Action outputs are invalidated before installation
  (including if package installation fails and uploads run with `always()`).
  Manifest mode deletes any prior source receipt/handoff and refuses a
  nonempty existing output directory, preserving existing contents rather
  than silently mixing cohorts.
- Local `ovk verify --manifest ... --advisory` remains an available
  explicitly scoped experiment. Its results must identify which claims and
  supplied materials were evaluated, and must not be presented as verification
  of the entire PR or its source revision.

This restriction is a publication-safety measure, not evidence authentication.
No existing signed source/evidence envelope, production approval, or
cross-repository certificate applicability follows. A future manifest
publication path must bind exact source revision, source-to-model coverage,
referenced material digests, results, and a qualified relying policy.

## Important limitations

- **Not source authenticity proof.** The GitHub event metadata, runner, checkout and storage remain unverified external observations. Raw parent shape is not a signed source/target validity certificate.
- **Not a signed evidence link.** This sidecar is **not yet incorporated into the canonical signed `EvidenceBundle` or `ovk-attestation-envelope`**. Its flags `bound_into_signed_evidence_envelope=false` and `production_reliance_authorized=false` are literal. Do not publish it as a portable signed verified-PR receipt.
- **Not general source correctness.** Diff inspection, compiled Assurance IR coverage and checker trust are separate. A structurally bound diff establishes *which Git tree was compared*, not that a machine claim comprehensively represents application source behavior.
- **Not PR-head verification.** The admitted default compares the event **base** to the synthetic **merge preview**. GitHub Checks created using `github.sha` are attributed to that merge SHA. For reviewer-facing PR-head checks, independently model *presentation SHA* and *verified subject SHA* before changing the Checks API target.
- **Shallow and private checkout prerequisites.** The default one-commit checkout may lack the base object. An explicit `fetch-depth: 2` on `actions/checkout` is recommended for a normal merge-preview PR; on some private/fork checkouts a missing base will require authenticated fetching. If absent and unfetchable, the Action fails closed. The first-user templates must be updated to guarantee this on the actual published Action revision.
- **Existing strict-profile no-go persists.** Historical issuer authorization, source-profile calibration, revocation, exact release identity and trustworthy evidence transport remain independently open under #25, #178, #195 and #205. No new `VALID`, production reuse, or automatic merge authorization.

## Adversarial qualification

Run `pytest -q tests/test_action_pr_source_binding_v1.py` and full repository CI on the exact PR SHA. The normal `action_default_diff_dogfood` workflow must pass from a genuine GitHub pull request event, exercising the new strict parent binding. A test pass on an earlier SHA does not authorize a later commit.

The next qualified iteration will integrate this sidecar's exact comparison/identity into the signed evidence envelope with a typed provenance contract and distinguish source-subject identity from GitHub Check presentation identity, including base drift, PR updates, and fork permissions. That later work requires independent oracle evaluation and reviewer usefulness. This PR is a bounded correctness prerequisite for the same open-source CLI/Action product, **not** a new speculative subsystem.
