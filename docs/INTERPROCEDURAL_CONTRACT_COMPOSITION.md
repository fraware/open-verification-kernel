# Interprocedural Contract Composition v1

OVK composes typed FunctionContract objects through a deliberately narrow class
of forwarding wrappers.

The base contract may be established directly from source:

    class AgentRepository:
        async def get(self, agent_id, *, workspace_id=None):
            agent = ...
            if workspace_id is not None and agent.workspace_id != workspace_id:
                return None
            return agent

which yields:

    pre:
      non_null(workspace_id)

    post:
      return.workspace_id == workspace_id

A transparent wrapper:

    class AgentService:
        def __init__(self):
            self._repo = AgentRepository()

        async def get(self, agent_id, *, workspace_id=None):
            return await self._repo.get(
                agent_id,
                workspace_id=workspace_id,
            )

inherits the contract by substituting the callee's parameter terms through the
call arguments.

Composition runs to a fixed point, so another forwarding layer can inherit the
already-derived AgentService contract.

## Supported forwarding forms

The v1 composer accepts:

- direct return of a call or awaited call;
- assignment from a call immediately followed by return of that variable;
- receivers constructed locally;
- receivers stored by simple self.field = Constructor(...) assignments in
  __init__;
- positional and keyword forwarding of wrapper parameters;
- non-null literal arguments, which discharge a non_null precondition;
- literal arguments in postconditions.

## Fail-closed cases

No wrapper contract is produced when:

- the callee has no established contract;
- the call target cannot be resolved to the contracted class/method;
- a required callee parameter is omitted;
- substitution uses an unsupported expression;
- the wrapper contains unsupported loop/try/match/with control flow;
- the wrapper has an ambiguous return shape.

The composer does not infer equivalence through arbitrary transformations. A
wrapper that computes a new resource key, mutates the returned object, catches
and rewrites failures, or conditionally changes the callee is outside v1.

## Fixed-point semantics

Contracts are added monotonically. Existing direct contracts are never replaced
by composed contracts. Iteration is bounded by the number of source methods, so
cycles cannot create an infinite derivation.

Each composed contract records its own source provenance and its content digest
includes the callee contract ID. This makes a downstream contract change when the
proof it depends on changes.
