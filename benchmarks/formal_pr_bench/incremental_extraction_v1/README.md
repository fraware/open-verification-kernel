# Incremental extraction scaling development benchmark

This benchmark isolates the source-extraction side of incremental Protected
Effect assurance.

For each configured source-set size N:

1. build one FastAPI Protected Effect source file plus N-1 unrelated Python files;
2. parse the base revision into a content-addressed ParsedPythonMaterials index;
3. create a head revision in which exactly one source file changes;
4. parse head once with no prior index (cold control);
5. parse head again while reusing the base index (warm incremental path);
6. compile the head Assurance IR from the validated warm index.

Deterministic asserted metrics:

- base fresh parses = N;
- cold head fresh parses = N;
- warm head fresh parses = 1;
- warm head reused AST entries = N-1;
- compiled Protected Effect coverage remains complete.

The benchmark also records wall-clock observations for indexing and compilation.
Those values are telemetry only. CI does not assert timing ratios or throughput.

Important remaining boundary:

The shared AST index makes parsing proportional to the changed file surface in a
long-lived worker. Function-contract inference and FastAPI semantic extraction
still walk the complete set of supplied ASTs. Therefore this benchmark does not
claim end-to-end O(delta) extraction yet.

The next target is content-addressed per-file semantic summaries and
dependency-aware recomposition.

These are public synthetic development workloads, not protected holdouts.
