# FastAPI dependency-to-effect profile

Profile identifier:

    assurance.fastapi.dependency_effects.ast_v1

This profile models a common production FastAPI authorization pattern where an
authorization dependency executes before the handler and the handler later
performs a security-sensitive service operation.

Example:

    @app.get("/workspaces/{workspace_id}/agents/{agent_id}")
    async def get_agent(
        workspace_id: str,
        agent_id: str,
        user = Depends(require_workspace_member),
    ):
        agent = await svc.get(agent_id, workspace_id=workspace_id)
        return agent

Repository policy explicitly declares:

- which dependency authorizes which route resource;
- which effects that dependency covers;
- which service calls are protected effects;
- which positional argument denotes resource identity;
- which keyword denotes resource scope.

For a same-tenant guarantee, the generated binding is:

    authorized workspace identity == acted resource scope

If the configured service call omits the scope keyword and the profile declares
that omission unconstrained, the extractor assigns a fresh symbolic scope. Z3
can then search for a cross-workspace counterexample.

No behavior is inferred merely from function names. All dependency and service
semantics are explicit profile assumptions.

The profile is advisory and narrow. Unsupported control flow or call shapes lower
coverage and prevent a PASS claim.
