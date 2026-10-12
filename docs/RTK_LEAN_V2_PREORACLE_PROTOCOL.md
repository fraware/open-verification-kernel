# RTK Lean v2: pre-oracle experiment integrity gate

**Status:** prospective *setup and source-discovery ledger*, before source-side
qualification, target-native adjudication or RTK SUT prediction on the newly
listed external candidates. This is **not** a completed or independently
reviewed preregistration and does not supersede the immutable RTK v0/v1
study records.

The operative tool is `experiments/rtk/lean_v2_preoracle.py`.
The discovery evidence is
`benchmarks/rtk_v2_lean/repository_discovery.preoracle.v1.json`.

## 1. Established baseline versus missing empirical component

OVK currently includes a Protected Effect evidence-reuse implementation and
the separately scoped research guarantee-transport gate (#179). That concrete
SUT does not process arbitrary Lean proof terms. The native Lean adapters
in #181 and #182 are **oracle development controls**, not a prediction
implementation or a formally proved RTK-to-Lean refinement.

A scientific benchmark requires a *frozen, genuinely predictive Lean
applicability SUT* with a declared, reproducible semantic interface.
The prospective holdout is **blocked** until that implementation exists.
Do not relabel a rule such as `proof bytes unchanged` as the operational
OVK SUT. An explicitly named byte-identity rule may be evaluated as a
**baseline**, provided it was registered before target outcomes.

## 2. Pre-outcome discovery ledger

On 2026-10-11, the following GitHub repository query was executed through
the connected GitHub search API:

```text
language:Lean stars:>50 created:<2025-01-01 archived:false
```

The first 20 returned repositories, in the provider's returned order, were
recorded verbatim in the separate discovery JSON file. The API supplied
its default relevance order; this is a **one-time snapshot**, not a
promise that later executions return identical ordering. No repository
source-theorem qualification or target-native adjudication was conducted
on this candidate ledger. `leanprover/lean4` is excluded because it was
used to develop the external native adapter in #182. The other entries
have status `UNQUALIFIED`, **not** `ELIGIBLE`.

Do not reorder the frozen discovery snapshot, insert favorable repos, or
silently substitute candidates. Record exclusions, licensing outcomes,
missing proof evidence, unsupported toolchains and operational failures.
Zero independently qualifying candidates is a valid result.

## 3. Prospective source-case qualification (proposed rule)

The following is a **proposed rule to receive an independent pre-outcome
review** before executing selection. It is recorded now and is not
retroactively asserted to be part of source selection v1.

1. Walk the 20 frozen repository records in increasing `rank` order.
   Exclude known adapter development repos, relevant prior research
   contamination, archives and repositories without a suitable license.
   Record each exclusion with an independently reviewable basis.
2. Select only Git SHA-addressable, first-parent historical transitions
   with a target-commit timestamp in
   `[2025-10-01T00:00:00Z, 2026-09-30T23:59:59Z]`.
   Record the commit identity and parent identity before inspecting
   *target proof outcomes*.
3. Qualify a named theorem using **source-side information only**.
   Its source-native proof bytes must exist, the claim must be typed,
   the required import/axiom context must be reconstructed, and native
   source acceptance must be recorded. Any unsupported environment is
   an exclusion, not a presumptive acceptance.
4. Restrict the initial narrow source family to self-contained Lean 4
   proof scripts with an exact theorem name, one unambiguous declaration
   and a replayable source claim. For this initial family, reject
   `sorry`, `admit`, `axiom`, `unsafe` and ambient imports.
   The implementation is intentionally conservative and can yield
   an empty corpus.
5. Freeze the selected source cases and target Git commit/path
   identifiers, claim/extractor identities, order, source evidence
   digests and source acceptance receipts. No target checker PASS/FAIL,
   RTK predictions or oracle failure taxonomy belongs in this freeze.
6. Subject to an independent feasibility review, take at most the
   first five eligible repositories and at most 100 chronological,
   source-qualified first-parent transitions overall. A repository
   must be exhausted under its frozen source-side rules before advancing
   to the next; no favorable outcome-based filtering.

Full selection code, first-parent ordering and eligible source-case
records still need implementation and independent review. Until then,
the discovery JSON is **candidate metadata**, not a fully admitted
confirmatory selection.

## 4. Exact phase boundary

`FrozenCohort` requires each case's repository, source/target commit
identities, source evidence digest, source-native acceptance receipt
digest, source context digest, target claim/context identity, selection
rank, and explicit source/oracle/SUT adapter identities. Digest values
are asserted by submitters; this module does not fetch external bytes.

`PredictionBundle` contains only predictions from the named SUT
commit and adapter. It cannot contain target oracle fields and must
cover every case in frozen order with the exact case input digest.

The `commit` subcommand produces a public prediction commitment and
a **private random 256-bit nonce**. The nonce must be stored with
restricted access outside the oracle runner and outside any public
GitHub repository. The public commitment is computed over the exact
typed predictions and frozen case digest, with domain separation.
Commit immutable predictions, receipt and a tamper-evident externally
timestamped signed event **before** target oracle work is made
accessible to the predictor. A SHA-256 commit alone does not prove the
order of events. The provided tool cannot verify GitHub permissions,
signed-timestamp authenticity or absence of earlier label access.

The oracle runner must operate in an isolated worktree and artifact
store and return `OracleBatch` under a predeclared oracle commit and
adapter. An independent native checker and a separately audited claim-
specific applicability argument are still necessary. Replaying source
bytes is insufficient when the semantic context has changed or cannot
be reconstructed.

Only after the precommitted inputs, model and baselines are immutable
should target-native oracle results be unblinded for joining. Existing
GitHub-visible target outcomes from #181–#182 are development-only
and **excluded from this holdout**.

## 5. Provisional score semantics

`score` verifies the private nonce against the public commitment;
all case/claim/context/evidence identities, SUT/oracle implementation
registrations, complete case order, and the two-axis adjudication input.
No missing case is dropped from the denominator.

It reports counts only, labeled `PROVISIONAL_UNAUDITED`.
`independent_oracle_execution_verified=False` and
`chronological_precommitment_verified=False` are fixed in the
output. These flags cannot be flipped by passing unit tests.
A purported old-evidence VALID prediction with an unresolved
historical applicability oracle remains `unadjudicated`.

No statistical bound is justified until external native witness
authentication, independent oracle adequacy, source selection
completeness, the chronology audit, and dependent-repository
uncertainty have been reviewed. The current protocol has at most
one primary claim per transition to avoid pseudoreplication.
No false-reuse or cost-savings measurements are reported here.

## 6. Non-negotiable acceptance criteria

- Verify exact selected source/target Git object identities and
  archive native verifier output bytes; recompute all SHA-256 values.
- Show a native positive certificate replay, a relevant historical
  applicability loss with separate fresh target PASS, inconclusive
  replay, checker/version drift, and statement/axiom mismatch.
- Commit a **real Lean applicability SUT** at a fixed Git SHA before
  examining the target oracle results. Distinguish it from fixed
  baselines and from the oracle.
- Independent reviewer validates experimental chronology and separation
  of access to source, target and prediction output environments.
- Pass focused unit tests, ordinary repository CI and a replayable
  native verifier workflow at the exact head.
- Submit an actual prospective preregistration and case freeze before
  asserting any confirmatory result. Treat later design changes as
  new versioned experiments.

The pilot remains non-controlling and does not affect OVK deployment
or security authorization decisions.
