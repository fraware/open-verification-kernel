# Sprint 4 Graph Update

The infrastructure exposure path now includes a graph-style normalization hook.

Implemented:

- Added `ovk.adapters.infra.graph`.
- Added graph reachability from external entrypoints to resources.
- Reachable confidential or restricted resources become exposure counterexamples through the existing evidence layer.
- Disconnected sensitive resources remain allowed.
- Empty graph normalization becomes invalid infrastructure input and requires review.
- Added `tests/test_infra_graph.py`.

Current limitation:

The graph hook is currently a lower-level normalization function. Extending the unified `normalize_infra_input` interface with a `graph` format was blocked by connector controls.
