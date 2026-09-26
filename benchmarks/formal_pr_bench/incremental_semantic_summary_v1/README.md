# Incremental semantic-summary scaling development benchmark

This benchmark measures per-file semantic extraction work after the shared AST,
function-contract summary, and FastAPI route-summary layers are enabled.

For each source-set size N:

1. build a base revision with one route file, one service file, and N-2 unrelated
   Python files;
2. index base ASTs, contract summaries, and route summaries;
3. modify only the service file so its successful-return contract changes from
   return.workspace_id == workspace_id to return.tenant_id == workspace_id;
4. build a cold head control with no prior summaries;
5. build a warm head using the base indexes;
6. compile head Assurance IR from the warm indexes.

Deterministic asserted warm work:

- fresh AST parses = 1;
- fresh contract file summaries = 1;
- fresh route file summaries = 1;
- reused contract summaries = N-1;
- reused route summaries = N-1.

Correctness assertion:

The route source is unchanged and its route summary is reused, yet the current
FunctionContract set is rebound into the route. The head compiler must therefore
report partial coverage with:

    required_scope_postcondition_missing:AgentService.get:workspace_id

This proves that summary reuse reduces source analysis work without freezing old
authorization semantics.

Cold controls still perform N AST parses and N per-file summaries.

Wall-clock fields are recorded for observation only. CI does not assert timing
ratios, CPU cost, throughput, or asymptotic runtime for global recomposition /
Assurance IR assembly.

These are public synthetic development workloads, not protected holdouts.
