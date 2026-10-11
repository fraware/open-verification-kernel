# RTK confirmatory repository qualification v0

Status: **EXHAUSTED_NO_QUALIFYING_REPOSITORIES**

This is the source-side qualification result for the repository discovery snapshot
frozen at commit `5ea024726ee46c74e5626b0c3048ebc0f902076e`.

No target oracle was executed. No RTK prediction was executed. The exact discovery
query was not broadened.

## Result

20 repositories were reviewed in the frozen provider order.

**Qualified repositories: 0.**

The failure is informative. The popular-FastAPI search universe is dominated by
frameworks, libraries, tutorials, and templates. The application-like repositories
with meaningful authorization tests use authorization mechanisms outside the
source-derived effectiveness theorems frozen in the current OVK FastAPI Protected
Effect profile.

The criteria were not weakened to manufacture a corpus.

## Most informative exclusions

### benavlabs/FastAPI-boilerplate

Cutoff: `4deb9c45f4298d4a84f005126f6ee8ccd823acf8`.

This repository has unusually strong independent authorization integration tests.
Its `require_permissions(...)` helper returns a nested FastAPI dependency. Its
decision depends on `crudauth` principal state, database-backed permission
loading, a closure-captured permission set, and superuser semantics.

That is a valuable future development case. The frozen OVK effectiveness extractor
does not establish this dependency shape, so it cannot enter the confirmatory
partition under the current SUT family.

### insistence/RuoYi-FastAPI

Cutoff: `726883f68ad21450ae47120d270895d9a5a9d69e`.

The repository has extensive authorization and identity tests and uses explicit
FastAPI dependency-based permission checks. The relevant dependencies are
implemented as callable classes and factories such as
`UserInterfaceAuthDependency(...)` / `CheckUserInterfaceAuth`.

The frozen source-derived effectiveness path proves only a narrow set of
top-level bearer/header/shared-secret function shapes. Treating the dependency
name as sufficient evidence of authorization would be unsound.

### fastapi-practices/fastapi-best-architecture

Cutoff: `123a44aed02daf5ea60d2a7469625c933d3bb759`.

Authorization uses dynamic JWT/RBAC and request-permission objects. This is outside
the frozen guard-effectiveness theorem.

### Buuntu/fastapi-react

The latest commit before the end of the study window is
`af17f2d422d0ebc5f173e83f2c6931045ab055b0` from 2022-02-18. It contributes no
transition in the frozen 2025-10-01 through 2026-09-30 study window.

## Scientific interpretation

This does not show that evidence transport lacks external cases.

It shows that **the current concrete claim family is too narrow to obtain a clean
confirmatory sample from the predeclared popular-FastAPI discovery universe
without changing source semantics**.

That is a capability-coverage result, not an RTK performance result.

## Consequence

Selection protocol v0 is closed. A subsequent attempt needs a new versioned
selection and/or a new versioned support family.

Candidate-specific semantics learned from the repositories above cannot be added
and then evaluated on the same repositories as pristine confirmation. If they are
used to develop reusable authorization semantics, they become development cases.

Machine-readable record:
`benchmarks/rtk_confirmatory/repository_qualification.v0.json`.
