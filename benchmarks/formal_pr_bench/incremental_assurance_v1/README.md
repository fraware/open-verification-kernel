# Incremental Assurance v1 development benchmark

This benchmark tests a work-count property of incremental Protected Effect
assurance.

For each configured assurance-surface size N:

1. construct N independent protected effects;
2. verify/cache the base revision with authenticated evidence;
3. change exactly one protected resource identity term in head;
4. execute incremental assurance against the warm cache;
5. count fresh evaluator requests and reused evidence records;
6. compare with the same head executed against an empty cache.

The expected warm-cache result is one fresh check and N-1 reused effects.
The cold-cache control requires N fresh checks.

The benchmark reports checker work count, not elapsed time, CPU cost, solver
complexity, or production throughput. Cache seeding itself requires the initial
base verification and is part of the amortized model.

These are public synthetic development workloads, not protected holdouts.
