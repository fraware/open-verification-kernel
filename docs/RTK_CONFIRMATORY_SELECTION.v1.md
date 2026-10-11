# RTK confirmatory repository selection v1

Status: frozen before theorem-shaped GitHub code discovery.

## Why v1 exists

Selection v0 is permanently closed with
`EXHAUSTED_NO_QUALIFYING_REPOSITORIES`.

Its repository-popularity query found mostly frameworks, libraries, tutorials,
templates, or applications whose authorization mechanisms exceeded the frozen
source-derived guard-effectiveness theorem.

v1 changes **discovery only**. It does not modify OVK extraction, Protected Effect
evaluation, guarantee binding, evidence reuse, or the SUT.

## Frozen support identity

OVK support commit:

`79370539ca9b26a0a6b01f6ac6ab6923243f40f4`

Guard-effectiveness implementation:

`ovk/compilers/authorization/route_dependency_effectiveness.py`

v1 searches only for source forms corresponding to the three effectiveness
families implemented at that frozen commit:

1. `fail_closed_header_shared_secret_v1`
2. `fail_closed_apikeyheader_shared_secret_v1`
3. `fail_closed_bearer_match_v1`

No new theorem family may be added during v1.

## Exact discovery queries

Run GitHub file search globally, on default branches, in this exact order:

1. `Header compare_digest HTTPException FastAPI`
2. `APIKeyHeader hmac compare_digest HTTPException FastAPI`
3. `Depends credentials HTTPException token FastAPI`

Request at most 50 file results per query.

These keyword searches are discovery mechanisms only. Matching text is not proof
that the frozen theorem applies.

## Repository ordering

Construct the repository candidate ledger as follows:

1. iterate queries in the order above;
2. iterate provider results in returned order;
3. extract repository identity from each result;
4. retain the first occurrence of each repository and discard later duplicate
   file hits from the discovery ordering;
5. freeze the resulting repository order before source-side qualification.

Persist every raw returned file hit separately so the deduplication is auditable.

## Repository exclusions

Use the same core exclusions as selection v0:

- repository owned by `fraware` or `SentinelOps-CI`;
- repository or transition already used to develop the relevant OVK source
  semantics;
- no open-source license;
- immutable source revisions unavailable;
- FastAPI usage is incidental rather than an application authorization surface;
- no independent repository-native oracle family exists before target inspection;
- no transition in the frozen study window;
- source case does not actually satisfy the frozen theorem after AST-level
  qualification.

A code-search hit does not override any exclusion.

## Study window

Target commit timestamp:

- start: 2025-10-01T00:00:00Z inclusive
- end: 2026-09-30T23:59:59Z inclusive

## Theorem-shaped qualification

A source case qualifies only if the exact source revision satisfies the same
source-shape predicate as the frozen OVK effectiveness extractor.

For example:

- a text occurrence of `compare_digest` is insufficient;
- a helper with additional unsupported control flow is insufficient;
- an imported library call whose behavior is not proved by the frozen extractor
  is insufficient;
- a route name or dependency name is never authorization evidence by itself.

The qualification record must identify which frozen effectiveness family applies
and the exact source path / function identity.

## Independent oracle family

Before a repository qualifies, identify a repository-native test or validation
family that exercises the same authorization claim without consuming OVK/RTK
objects.

The oracle family itself is frozen by file/path/test selection rules before any
target transition outcome is executed.

## Selection stopping rule

Walk the frozen deduplicated repository list.

Select the first five repositories that satisfy all repository-level gates.

If fewer than five qualify after the discovered repository list is exhausted,
close v1 with that smaller set. Do not add queries during v1.

Within selected repositories, freeze source-qualified FIRST_PARENT transitions in
chronological order, up to 100 independent transitions total or history
exhaustion.

## Contamination

Any repository used to change:

- the guard-effectiveness theorem;
- source extraction;
- Protected Effect evaluation;
- guarantee binding;
- evidence-reuse semantics;
- oracle adapter semantics

moves to development status and is excluded from v1 confirmation.

## Prohibitions

During discovery and source-side qualification:

- NO target oracle execution
- NO RTK prediction
- NO target-label inspection for case selection
- NO semantic extension
- NO source-profile weakening
- NO candidate-specific authorization mapping used as proof

The first v1 artifact is the immutable raw code-search hit ledger and deduplicated
repository order.
