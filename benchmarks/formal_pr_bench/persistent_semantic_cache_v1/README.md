# Persistent semantic-cache scaling development benchmark

This benchmark tests whether per-file Python semantic summaries survive worker
process boundaries.

For each source-set size N:

1. build and persist a base cache using one cache object;
2. instantiate a new cache object against the same filesystem root to simulate a
   fresh worker;
3. load an unchanged head revision with identical source bytes;
4. load a second head revision where only service.py changes its successful-return
   contract from workspace_id to tenant_id;
5. compile both heads from the persistent summaries.

Deterministic assertions:

Unchanged fresh worker:
- cache hits = N;
- parses = 0;
- semantic summary misses = 0;
- extraction remains complete.

One-file semantic change:
- cache hits = N-1;
- misses/parses = 1;
- only one fresh contract and route summary is generated;
- unchanged route summary is loaded from persistent JSON;
- compiler rebinds it against the changed service contract;
- extraction becomes partial with the expected missing workspace postcondition.

At N=256 this means a fresh worker performs zero parses for an unchanged revision,
and one parse after one service file changes.

The benchmark records wall-clock observations but makes no CI timing or throughput
claim. Full global summary recomposition and Assurance IR assembly still occur.

These are public synthetic development workloads, not protected holdouts.
