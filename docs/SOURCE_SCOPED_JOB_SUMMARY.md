# Read-only source-scoped PR summary — developer preview

**Status: unmerged development feature, not part of published `v1.2.1`.**
The historical Action does not contain this feature. This document records a
candidate [read-only summary workflow](https://github.com/fraware/open-verification-kernel/pull/227),
pending its exact-commit CI, source-path review, release governance and a
consenting independent adoption experiment. No production relying authority
or externally calibrated verification claim is established.

## Reviewer experience

A consenting repository enables the OVK composite Action on an ordinary
`pull_request` workflow with:

- a full-SHA-reviewed Action revision and `actions/checkout` at the normal
  GitHub merge-preview event SHA, with a sufficiently deep checkout;
- `mode: advisory`, `use-check: "true"`, **no** explicit `changed-files`
  or `verification-manifest` input, `emit-check: "false"`,
  `post-comment: "false"`;
- job `permissions: {contents: read}` and no untrusted PR secrets.

Only in that bounded default path, the Action reads the local
`ovk-evidence.json` and `ovk-source-binding.json`. It rejects absent,
unbound, structurally inconsistent or mismatched source identifiers before
appending a concise summary to GitHub's native `GITHUB_STEP_SUMMARY` file.
This uses the existing workflow's job-summary presentation; no PR comment,
GitHub Check-write permission, third-party service, or hosted account is
needed.

The summary includes the *recorded scoped* checker decision, the observed
merge-preview, original PR-head and base SHAs, SHA-256 of the observed diff
and of the exact local evidence bytes. It states that source/event
authenticity, complete source-to-model correspondence, signed envelope
binding, production reliance, and whole-PR security **are not established**.
A recorded `allow` never authorizes merging. No user-controlled source
snippet or raw code is copied into the summary.

The job summary is a *review-navigation and evidence-identification artifact*,
not a signed certificate. Its identifiers are useful for comparing local
reports and locating the underlying artifacts. A SHA-256 digest is tamper
evidence only relative to a trusted expected digest; it does not establish
the authenticity of the evidence or the GitHub runner.

**Portable human-review artifact (unreleased draft #228):** The same validated
text is also saved as `ovk-advisory-pr-summary.md` and included in the
existing OVK evidence-artifact upload. A teammate can inspect the report with
its exact source/decision limitations without copying the generic
`ovk-pr-comment.md`, which lacks these prominent source-binding caveats.
The standalone Markdown report is *not* a cryptographic certificate, and the
upload does not itself authenticate the file or event. Failed source validation
deletes any stale portable report before an always-running upload occurs.
The renderer deliberately excludes raw PR diffs and source excerpts from its
Markdown; the recorded digest supports subsequent independent comparison.
Native GitHub job-summary presentation remains available in parallel.

## Reuse across repositories and CI systems

The renderer itself uses only Python's standard library:

```bash
python scripts/render_source_bound_job_summary.py \
  --evidence ovk-evidence.json \
  --source-binding ovk-source-binding.json \
  --diff .ovk-pr.diff \
  --output advisory-summary.md \
  --portable-output ovk-advisory-pr-summary.md
```

The evidence, source receipt, and **exact binary diff bytes** must come
from the same ordinary, internally prepared source-bound OVK PR run. The
renderer recomputes the input diff digest and refuses a changed or missing
diff; it also checks the complete source tree SHA field and agreement of
the evidence subject with the observed merge preview. Copying fixtures, passing caller-selected diffs,
relabeling PR heads, or using a multi-lane manifest is deliberately refused.
The renderer appends instead of overwriting an existing summary, so
multiple independent tools in the same CI job retain their own sections.
The file can be used in a different CI provider only if the exact local
observation contract is reproduced and checked; the script itself does not
authenticate third-party events.

Use this first as a **read-only advisory preview**, strictly with maintainer
consent and human review. Existing public release controls in issue #25 and
source-model/refinement qualification in issue #195 remain separate.

## Distribution and utility measurement

Track the adoption chain prospectively, with source evidence and no inflated
marketing counts:

1. consented outside-repository installation and setup time;
2. first natural PR with a complete, intelligible, source-identified
   observation and explicit unsupported/unknown cases;
3. an independent reviewer reading the summary and the underlying evidence,
   including reviewer minutes, useful findings and erroneous alerts;
4. a second natural PR and independent teammate adoption;
5. legitimate cross-repository reuse of an explicitly specified claim, with
   applicability conditions and independent review, not a copy-pasted PASS.

Treat the job summary's page views and GitHub stars as distribution indicators,
not as formal assurance, effective vulnerability detection, or economic value.
A pilot with no qualifying claims is a valid null result; report coverage and
attrition rather than claiming a perfect false-positive or false-negative rate.
