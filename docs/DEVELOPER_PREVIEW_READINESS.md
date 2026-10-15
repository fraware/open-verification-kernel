# Developer preview readiness and first-user activation

**Status: NOT LAUNCH-AUTHORIZED.** This checklist is for the maintainer and an independent release reviewer. Do not present green PR CI or a draft PR as a published, signed production version.

## The promise to test

For one supported change in a real PR, the developer receives a reviewable machine-readable result that identifies (a) the bounded claim checked, (b) what evidence supports the outcome and the relevant source revision, (c) unsupported/unknown conditions, and (d) the exact next verification action. The objective is to make security-sensitive AI-authored changes reviewable with accountable evidence. Do not call an entire repository or PR formally verified.

**Distribution strategy:** open-source CLI and composite GitHub Action as the first developer-native interface; shareable PR reports once their source revision and trust scope are reliably bound; GitHub App and optional organization service only following repeated external demand. A standalone hosted web application is not a release prerequisite.

## First local demonstration (unreleased checkout only)

The following runs against the **source checkout**, not a published distribution. Use Python 3.10–3.12 in a clean environment:

```bash
git clone https://github.com/fraware/open-verification-kernel.git
cd open-verification-kernel
python -m pip install -e '.[dev]'
ovk init
ovk doctor
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
```

Inspect the generated `ovk-evidence.json`, `ovk-pr-comment.md`, and `ovk-evidence-quality.json`. These are **bounded development fixtures** for product understanding, not independent accuracy evidence. Try the deterministic failing/repair walkthrough with:

```bash
python examples/repair_loops/ci_secrets/demo_repair_loop.py
```

The emitted outputs must be explained in the context of the admitted inputs and compiler/checker assumptions. In advisory mode the job can succeed while the **recorded decision** remains `block`, `needs_review`, or `unknown`.

## Historical release versus current development

As checked October 15, 2026, `v1.2.1` is the last public GitHub Release; `v1.3.0-rc.1` **does not exist as a public tag**. The historical source commit for `v1.2.1` is `a27d5720f4350c00bca34f71d991c31f5a2f38c7`, whose **old Action implementation silently falls back from failed versioned PyPI installation to its checkout**. Its annotated tag is unsigned and the Release object is not marked immutable. This is insufficient to claim an authenticated, fail-closed distribution solely from the Action reference.

Draft [PR #220](https://github.com/fraware/open-verification-kernel/pull/220) corrects the current checkout's installer; it does **not** retroactively patch the old Action. Do not advertise a corrected release until it is independently authorized and published.

## Release GO / NO-GO acceptance criteria

- [ ] GitHub administrator creates active branch and tag rulesets and the effective constraints are independently read back. See [issue #25](https://github.com/fraware/open-verification-kernel/issues/25).
- [ ] The complete exact SHA candidate passes CI, multi-OS/Python reproducibility, native backend matrices, package build, outside-checkout smoke, templates, and Action dogfood.
- [ ] The requested distribution version either installs exactly or the installation fails, with no silent checkout fallback; negative test runs on each supported platform.
- [ ] Final README, example workflows, security support policy, attribution, and license are consistent with the publication state. No nonexistent tag is in **active** copyable examples.
- [ ] The signed annotated release tag directly identifies the authorized source SHA and GitHub reports verified signature; new tag-bound release, holdout, consumer, and ledger checks meet [RELEASE.md](RELEASE.md).
- [ ] Sigstore material is cryptographically verified against exact published distribution hashes, and PyPI read-back equals the authorized bytes. Report historical artifact-signing and tag-signing claims separately.
- [ ] One external maintainer explicitly consents to a **nonblocking advisory** pilot with their normal PR stream. A reviewer inspects at least one real supported/unsupported change, recording denominators, unknowns and review time. Small samples cannot qualify strict enforcement.
- [ ] A new developer outside the maintainer team completes the **source checkout / released-wheel** first-run task and explains one result, without private fixture knowledge or maintainer intervention. Record errors and elapsed setup time.

All boxes are independent; the absence of any source/provenance or policy evidence prohibits broad claims. The presence of published code does not grant automatic merge authority.

## Adoption and repeat-use metrics

Measure the conversion sequence **README viewed → independently installed → first meaningful report → second natural PR reviewed → teammate adoption**. Exclude bots and the maintainer's own controlled repositories from independent organization counts. Track unsupported source coverage as prominently as supported paths. Record reviewer time and avoided rechecking separately from compute duration; do not infer a breach-prevention rate from a tiny sample.

**Primary North Star metric:** independently reviewed, consequential software guarantees that remain justified across successive changes, with observed revalidation effort and explicit unknowns. Stars, website impressions, and reposts are secondary distribution signals, not proof of customer value.

## Expansion decision

A public GitHub App follows repeated Action use **and** demonstrated onboarding friction that an App meaningfully reduces. A hosted evidence history follows paid demand for multi-repository persistence, access control, revocation, audit policy, and operational support. Public viral marketing follows a real consented demonstration with exact version-pinned, replayable materials and carefully stated guarantees.
