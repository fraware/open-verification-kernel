# RTK confirmatory repository selection v0

Status: frozen before repository discovery for the first post-audit confirmatory
candidate search.

## Scope

The first confirmatory family is restricted to the existing governed FastAPI
Protected Effect semantics on OVK main commit:

`79370539ca9b26a0a6b01f6ac6ab6923243f40f4`

No source-profile semantics may be added or weakened in response to a discovered
candidate and still count that same candidate as confirmatory evidence.

## Discovery query

Repository discovery uses GitHub repository search with the exact query:

`fastapi language:Python stars:>=500 fork:false archived:false`

Discovery snapshot date: **2026-10-11**.

Take the first 20 repositories returned by the GitHub repository-search API in its
returned order. Save that list unchanged before source-profile qualification.

The API ranking is treated as an external discovery mechanism, not as a scientific
ranking. The frozen returned list is the reproducibility object.

## Repository exclusions

Exclude only with an explicit reason code.

Predeclared exclusions:

- repository owner is `fraware` or `SentinelOps-CI`;
- repository is an OVK consumer / development repository already used to tune the
  relevant FastAPI Protected Effect machinery;
- no open-source license is exposed by the repository;
- repository cannot be checked out at immutable commits;
- FastAPI is incidental documentation/example material rather than part of the
  evaluated application surface;
- no source revision in the study window can be represented by the frozen FastAPI
  source profile without adding candidate-specific semantics;
- no independent repository-native authorization oracle family exists before
  target outcome inspection.

Every excluded repository remains in the discovery ledger.

## Independent oracle requirement

For this family, the preferred independent oracle is a repository-native
authorization test or integration-test family that predates the target transition.

The oracle must exercise the substantive protected effect / access-control claim
without consuming:

- OVK Assurance IR;
- Protected Effect semantic-slice digests;
- RTK reuse decisions;
- RTK footprints;
- RTK predictions or rationale codes.

A test introduced only in response to the evaluated target transition is useful
development evidence and cannot serve as the sole confirmatory oracle for that
transition.

A public advisory or merged security fix alone is not sufficient. The case must
begin from source evidence that was accepted at the source revision.

## Study window

For each selected repository, use only first-parent transitions whose target
commit timestamp is between:

- 2025-10-01T00:00:00Z inclusive
- 2026-09-30T23:59:59Z inclusive

This ends before the current confirmatory design work.

## Transition enumeration

For every eligible repository:

1. enumerate every non-root FIRST_PARENT transition in the study window;
2. order transitions by target commit timestamp ascending, then target SHA;
3. perform source-side qualification only;
4. freeze all source-qualified cases before executing any target oracle;
5. retain source-side operational failures and exclusions with reason codes.

Do not select transitions from security-fix labels, target failures, RTK
predictions, or known outcome convenience.

## Source-side qualification

A transition enters the pre-oracle case pool only if, using the source revision:

- a stable protected-effect / guarantee identity is constructible;
- the frozen FastAPI source profile reports complete enough material for the
  source claim;
- source evidence is successfully established and sealed;
- the independent oracle adapter family already applies to the same claim;
- exact source evidence and SUT input identities are content-addressed.

Target-side test result is not consulted during this step.

## Repository stopping rule

Walk discovery repositories in frozen API order.

Select the first **five** repositories that pass the source-side repository
eligibility rules.

If fewer than five qualify among the first 20 discovery results, stop with the
qualified set obtained. Do not broaden the query during v0.

## Case stopping rule

Within selected repositories, retain source-qualified transitions in chronological
order until either:

- 100 independent source-qualified transitions are frozen across the selected
  repositories; or
- all transitions in the fixed study window are exhausted.

This is a corpus-construction target, not a claim of statistical adequacy.

The effective false-reuse denominator will be the resolved non-VALID transition
opportunities after independent oracle adjudication.

## Contamination rule

If a discovered repository causes any substantive change to:

- FastAPI extraction semantics;
- Protected Effect evaluation semantics;
- guarantee binding semantics;
- reuse eligibility semantics;
- oracle adapter semantics;

then that repository and all transitions used to motivate the change move to the
development partition.

A replacement confirmatory repository is chosen by continuing down the already
frozen discovery list.

## Existing external-security registry

The pre-existing
`benchmarks/assurance_qualification/external_candidates.v1.json` remains useful
for external coverage accounting.

Its security-fix cases are not automatically RTK transport cases because transport
requires accepted source evidence. They may enter this study only if they satisfy
the same source-side and oracle rules above without changing frozen semantics.

## Next artifact

The first post-freeze action is to persist the exact 20-repository discovery
snapshot, including repository identity, search order, license metadata where
available, and source-side eligibility status.

No target oracle is executed during discovery.
