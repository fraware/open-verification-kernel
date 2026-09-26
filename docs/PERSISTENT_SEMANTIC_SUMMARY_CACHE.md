# Persistent Python Semantic Summary Cache

The bounded Python Protected Effect source profile can persist per-file semantic
summaries across worker processes.

## Stored object

The cache stores one JSON record per repository-relative path and source content
digest.

A valid-source record contains:

- ContractFileSummary
- RouteFileSummary

A syntax-error record contains only the syntax failure.

AST objects are never serialized.

## Cache identity

Each record key binds:

- semantic-summary cache schema version;
- semantic-summary implementation version;
- OVK version;
- repository-relative source path;
- exact source content digest.

The record also carries:

- the full key components;
- key digest;
- payload;
- payload digest.

Reads validate every one of those fields before reconstructing typed summaries.
Corrupt or incompatible records are cache misses.

## Fresh worker behavior

A worker with no in-memory state computes each head source digest and checks the
persistent cache.

For a valid hit:

    source bytes are not parsed
    AST is not constructed
    contract summary is reconstructed from JSON
    route summary is reconstructed from JSON

For a miss:

    source is parsed once
    both semantic summaries are extracted
    the content-addressed bundle is persisted

Cached syntax failures are also reusable, preventing repeated parsing of an
unchanged malformed file while preserving the same explicit extraction failure.

## Semantic rebinding

Persistent summaries carry source syntax/contract facts only.

The FastAPI compiler still:

- globally recomposes FunctionContract dependencies;
- rebinds route summaries against the current profile;
- rebinds route summaries against the current composed contract set;
- rebuilds the complete head Assurance IR.

A cached route therefore responds to a changed service contract or profile.

## Current trust boundary

The cache is an optimization. Cache corruption, wrong versions, source digest
mismatch, malformed typed payloads, or path mismatch degrade to fresh parsing and
summary generation.

No cache hit can directly emit a verification PASS.

## Remaining scaling work

The remaining repository-size-dependent work is dominated by lightweight global
summary graph processing and complete Assurance IR assembly.

A future dependency-aware incremental compiler can preserve prior per-route
semantic IR fragments and recompute only:

    changed source summaries
    transitive contract dependents
    routes consuming those contracts
    affected Protected Effects

That is the path from O(delta) source analysis to O(delta + dependency closure)
semantic compilation.
