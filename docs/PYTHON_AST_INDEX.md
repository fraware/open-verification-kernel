# Shared Python AST Index

The FastAPI Protected Effect source profile parses Python source through a shared
content-bound AST index.

## Single compile

Without a shared index, three internal consumers previously parsed the same head
source set independently:

1. typed function-contract inference;
2. legacy ResourceReturnContract projection;
3. route/protected-effect extraction.

The compiler now parses each head source file once. Contract inference and route
extraction consume the same AST objects, and the legacy projection reuses the
already inferred FunctionContract set.

## Cross-revision reuse

ParsedPythonMaterials records, for every head path:

- source content digest;
- parsed AST or syntax-error result;
- number of fresh parses;
- number of reused entries.

A later head revision can be indexed with reuse_from=<prior index>.

For each file:

    same path + same source digest
        -> reuse prior AST/syntax error

    new or changed digest
        -> parse once

If one file changes in an N-file source set, the new index therefore performs
one fresh parse and reuses up to N-1 entries.

## Compiler binding

FastApiDependencyEffectExtractor.compile accepts an optional parsed_index.

A supplied index is trusted only after its complete path->content-digest map
matches the supplied head materials. A stale or mismatched index raises
ValueError and is never consumed.

The historical compile(materials, profile) API remains unchanged and creates its
own fresh index.

## Current boundary

This is an in-memory parse cache. It does not yet persist Python AST objects
across workers or processes.

It also does not make semantic extraction fully incremental. Contract inference
and route analysis still walk ASTs for all files in the supplied head revision,
even when the parser reuses unchanged trees.

The next scaling layer is content-addressed semantic summaries:

    source digest
      -> per-file extracted contracts/routes/effects
      -> dependency-aware recomposition

That would move semantic extraction itself toward work proportional to the
changed source surface.
