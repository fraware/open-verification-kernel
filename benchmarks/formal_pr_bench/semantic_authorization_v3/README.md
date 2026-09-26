# Semantic Authorization v3 development cases

These cases exercise interprocedural authorization and resource-scope reasoning.

The first case is a public, provenance-grounded reduction of a cross-workspace
FastAPI authorization flaw. It contains two source units:

1. a route protected by Depends(require_workspace_member);
2. a service method whose source establishes that a successful return belongs to
   workspace_id when that non-null argument is supplied.

The secure and vulnerable route variants differ only in the service call:

    await svc.get(agent_id, workspace_id=workspace_id)

versus:

    await svc.get(agent_id)

The source-derived service contract, not a manually declared sink-scope rule,
provides the proof step from the call argument to the returned resource scope.

This is public development data with high contamination risk. It is not eligible
for protected holdout scoring.
