# Persistent incremental FastAPI fresh-worker scaling benchmark

This public development benchmark measures deterministic semantic work after the
complete incremental FastAPI state is persisted across worker processes.

Each compile constructs new cache objects. Reuse therefore comes from persisted
JSON records, not in-memory Python object identity.

For each repository size N in 8, 64, and 256 files, four states are observed.

## Base population

The first worker populates:

- per-file persistent semantic summaries;
- dependency-aware contract composition state;
- bound FastAPI semantic fragments.

Base work is recorded for context only.

## Unchanged fresh worker

A new worker compiles the same source bytes at a new revision.

Required work:

    fresh parses = 0
    recomposed contracts = 0
    rebound semantic fragments = 0

All N semantic summaries and all N semantic fragments are reused.

## One unrelated file change

A new worker sees one unrelated Python file change.

Required work:

    fresh parses = 1
    recomposed contracts = 0
    rebound semantic fragments = 1

These counts remain constant from 8 to 256 files.

## Low-level contract change

From a separate secure baseline, one repository method changes its established
attribute from workspace_id to tenant_id.

The route source, service wrapper, and facade wrapper remain unchanged.

Required work:

    fresh parses = 1
    invalidated contract stable names = 3
    recomposed forwarding contracts = 2
    rebound semantic fragments = 2

The two rebound fragments are the changed repository source file and the
unchanged route that consumes the changed facade contract. Unrelated fragments
remain reusable.

These counts also remain constant from 8 to 256 source files.

## Correctness

Every warm result is compared with a fresh full
FastApiDependencyEffectExtractor compile. Exact canonical Assurance IR equality
is required.

Wall-clock fields are observational only. CI makes no runtime-complexity claim
from timing measurements.

These are synthetic public development workloads, not protected holdouts.
