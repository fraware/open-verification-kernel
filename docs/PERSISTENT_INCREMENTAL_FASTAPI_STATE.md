# Persistent Incremental FastAPI State

The bounded FastAPI Protected Effect compiler can persist its dependency-aware
semantic compilation state across worker processes.

This layer builds on:

- persistent per-file semantic summaries;
- incremental function-contract composition;
- dependency-valid FastAPI semantic fragments.

## Stored state

One JSON record per repository/profile stores:

- prior head revision metadata;
- source content digests;
- profile semantic digest;
- stable function-contract versions;
- typed per-file FastApiFileSemanticFragment objects;
- complete incremental contract-composition state;
- prior Assurance IR digest.

ASTs and executable Python objects are never serialized.

## Cache identity

The stable cache key binds:

- persistent-state schema version;
- implementation version;
- OVK version;
- repository identity;
- profile semantic digest.

The record also carries a key digest and payload digest.

Reads reconstruct every typed model and reject records when:

- key components differ;
- key or payload digest fails;
- repo/profile identity differs;
- typed reconstruction fails;
- fragment map/path identity differs;
- fragment source digest disagrees with stored source state;
- fragment profile digest disagrees with the cache profile;
- stored contract versions disagree with reconstructed contract state.

Every rejection becomes a cache miss.

## Fresh-worker pipeline

A fresh worker can execute:

    current source files
      -> persistent per-file semantic-summary cache
      -> one parse/summary for each changed file
      -> load prior dependency-aware FastAPI state
      -> incremental contract composition
      -> dependency-valid fragment reuse/rebinding
      -> complete current Assurance IR
      -> persist new semantic state

For an unchanged five-file workload after a worker restart:

    fresh parses = 0
    reused semantic summaries = 5
    recomposed contracts = 0
    rebound route fragments = 0

For one unrelated changed file:

    fresh parses = 1
    recomposed contracts = 0
    rebound fragments = 1

For a low-level repository contract change:

    fresh parses = 1
    recomposed contracts = affected forwarding closure
    rebound fragments = changed source file + consuming routes

## Concurrency and stale state

The record is a latest-state optimization, not a proof artifact.

Writes use atomic replacement. A stale state from an older revision or another
branch is safe to consume because every reuse decision is rebound against current
source digests, profile digest, candidate fingerprints, contract versions, and
fragment dependencies. Stale state can reduce cache hit rate; it cannot directly
produce a verification PASS.

Repository identity is required for higher-level state persistence. If
AuthMaterials.repo is absent, the compiler still uses the per-file semantic
summary cache but skips loading and writing the FastAPI state cache.

## Equivalence

Persistent reuse is accepted only as an optimization.

Tests compare every resulting canonical Assurance IR payload with a fresh full
FastApiDependencyEffectExtractor compile across unchanged revisions, unrelated
changes, and transitive contract changes.

The intended fresh-worker semantic work bound is:

    O(changed files + changed contract dependency closure
      + affected route fragments)

instead of O(repository size).
