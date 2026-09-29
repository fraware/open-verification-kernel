# Interprocedural resource-return contracts v1

OVK now has a restricted source-derived contract for service methods that guard a
returned resource's scope.

The accepted pattern is intentionally narrow:

    async def get(self, agent_id, *, workspace_id=None):
        agent = ...
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

From this, OVK derives:

    return != None and workspace_id != None
        => return.workspace_id == workspace_id

The contract records:

- the qualified method name;
- the scope parameter;
- the returned resource scope attribute;
- whether the proof depends on a non-null argument;
- exact source provenance.

The v1 inferencer rejects methods with unsupported loops, try/match/with control
flow, multiple successful return values, or ambiguous scope-rejection guards.

It does not infer primary-key identity from ORM calls and does not claim general
functional correctness. Its only claim is the successful-return scope
postcondition established by the explicit rejecting branch.
