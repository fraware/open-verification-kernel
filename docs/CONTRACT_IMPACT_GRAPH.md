# Contract Impact Graph v1

OVK uses the interprocedural contract graph to determine which assurance
surfaces become stale when a function contract changes.

## Stable and version identity

A FunctionContract has two identities:

- qualified_name is the stable callable identity across revisions;
- contract_id is the content identity of one semantic contract version.

A composed contract records stable dependencies through depends_on. Its
contract_id also incorporates the callee contract version, so semantic changes
propagate into derived contract versions.

Example:

    AgentRepository.get
          |
          v
    AgentService.get
          |
          v
    AgentFacade.get

If AgentRepository.get changes, the transitive contract impact is all three
stable names.

## Call-site consumption

A ContractUse records one concrete consumption of a contract:

- exact contract_id;
- stable qualified_name;
- acted resource;
- established return attributes;
- source provenance.

SemanticPath.contract_use_ids connects that use to protected effects and resource
bindings.

This gives the incremental chain:

    changed contract
        -> transitive dependent contracts
        -> concrete contract uses
        -> semantic paths
        -> protected effects / bindings

## Revision deltas

diff_function_contracts compares base and head by stable qualified name and
reports:

- added;
- removed;
- version_changed.

compute_contract_delta_impact evaluates the changed names against both the base
and head graphs. This matters for removals: a deleted contract or call site no
longer exists in head, but its previously protected surface still needs to be
reported as invalidated.

The result keeps base and head impacts separately and also exposes their union.

## Trust and scope

This graph does not prove the underlying contracts. It propagates invalidation
over already extracted Assurance IR relationships.

It is deliberately not a complete source-code change-impact engine. A route
change, policy change, effect change, or new unsupported semantic construct can
require verification independently of a FunctionContract delta. Those changes
remain governed by OVK's ordinary source extraction and verification planning.

The v1 graph answers the narrower question:

    Given a changed function contract, which contract-derived assurance claims
    and protected effects depend on it?

That is the primitive needed for incremental proof repair and near-zero marginal
verification work on unaffected software.
